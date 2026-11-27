#include "ash_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <bcrypt.h>
#include <process.h>
#include <psapi.h>
#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif
#else
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <sched.h>
#include <signal.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <unistd.h>
#endif

static const uint8_t k_v4mapped_prefix[12] = {
    0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0xFFu, 0xFFu
};

bool ash_ep_eq(const ash_ep_t *a, const ash_ep_t *b) {
    if ((a == NULL) || (b == NULL)) return false;
    if ((a->fam == 0u) || (a->fam != b->fam) || (a->port != b->port)) return false;
    size_t len = (a->fam == 4u) ? 4u : 16u;
    return memcmp(a->ip, b->ip, len) == 0;
}

bool ash_ep_same_ip(const ash_ep_t *a, const ash_ep_t *b) {
    if ((a == NULL) || (b == NULL) || (a->fam == 0u) || (a->fam != b->fam)) return false;
    size_t len = (a->fam == 4u) ? 4u : 16u;
    return memcmp(a->ip, b->ip, len) == 0;
}

bool ash_ep_is_private(const ash_ep_t *ep) {
    if (ep == NULL) return false;
    if (ep->fam == 4u) {
        uint8_t b0 = ep->ip[0];
        uint8_t b1 = ep->ip[1];
        if ((b0 == 10u) || (b0 == 127u)) return true;
        if ((b0 == 172u) && (b1 >= 16u) && (b1 <= 31u)) return true;
        if ((b0 == 192u) && (b1 == 168u)) return true;
        if ((b0 == 169u) && (b1 == 254u)) return true;
        if ((b0 == 100u) && (b1 >= 64u) && (b1 <= 127u)) return false; /* CGNAT is WAN-like */
        return false;
    }
    if (ep->fam == 6u) {
        bool is_lo = (ep->ip[15] == 1u);
        for (size_t i = 0u; i < 15u; ++i) {
            if (ep->ip[i] != 0u) is_lo = false;
        }
        bool is_ula = (ep->ip[0] & 0xFEu) == 0xFCu;
        bool is_ll  = (ep->ip[0] == 0xFEu) && ((ep->ip[1] & 0xC0u) == 0x80u);
        return is_lo || is_ula || is_ll;
    }
    return false;
}

void ash_ep_from_sockaddr(const struct sockaddr_storage *ss, uint8_t proto, ash_ep_t *out) {
    if ((ss == NULL) || (out == NULL)) return;
    memset(out, 0, sizeof(*out));
    out->proto = proto;
    if (ss->ss_family == AF_INET) {
        const struct sockaddr_in *s4 = (const struct sockaddr_in *)ss;
        out->fam  = 4u;
        out->port = ntohs(s4->sin_port);
        memcpy(out->ip, &s4->sin_addr, 4u);
    } else if (ss->ss_family == AF_INET6) {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)ss;
        out->port = ntohs(s6->sin6_port);
        const uint8_t *raw = (const uint8_t *)&s6->sin6_addr;
        if (memcmp(raw, k_v4mapped_prefix, 12u) == 0) {
            out->fam = 4u;
            memcpy(out->ip, raw + 12u, 4u);
        } else {
            out->fam = 6u;
            memcpy(out->ip, raw, 16u);
        }
    }
}

socklen_t ash_ep_to_sockaddr6(const ash_ep_t *ep, struct sockaddr_in6 *sa6) {
    if ((ep == NULL) || (sa6 == NULL)) return 0;
    memset(sa6, 0, sizeof(*sa6));
    sa6->sin6_family = AF_INET6;
    sa6->sin6_port   = htons(ep->port);
    if (ep->fam == 4u) {
        uint8_t *dst = (uint8_t *)&sa6->sin6_addr;
        memcpy(dst, k_v4mapped_prefix, 12u);
        memcpy(dst + 12u, ep->ip, 4u);
        return (socklen_t)sizeof(*sa6);
    }
    if (ep->fam == 6u) {
        memcpy(&sa6->sin6_addr, ep->ip, 16u);
        return (socklen_t)sizeof(*sa6);
    }
    return 0;
}

static bool parse_port_str(const char *s, uint16_t *out_port) {
    if ((s == NULL) || (*s == '\0')) return false;
    uint32_t acc = 0u;
    for (size_t i = 0u; s[i] != '\0'; ++i) {
        if ((s[i] < '0') || (s[i] > '9')) return false;
        acc = (acc * 10u) + (uint32_t)((uint8_t)s[i] - (uint8_t)'0');
        if (acc > 65535u) return false;
    }
    if (acc == 0u) return false;
    *out_port = (uint16_t)acc;
    return true;
}

bool ash_ep_parse(const char *ip_port, uint16_t default_port, ash_ep_t *out) {
    if ((ip_port == NULL) || (out == NULL)) return false;
    memset(out, 0, sizeof(*out));
    char host[128];
    uint16_t port = default_port;

    if (ip_port[0] == '[') {
        const char *rb = strchr(ip_port + 1, ']');
        if (rb == NULL) return false;
        size_t hlen = (size_t)(rb - (ip_port + 1));
        if ((hlen == 0u) || (hlen >= sizeof(host))) return false;
        memcpy(host, ip_port + 1, hlen);
        host[hlen] = '\0';
        if (rb[1] == ':') {
            if (!parse_port_str(rb + 2, &port)) return false;
        } else if (rb[1] != '\0') {
            return false;
        }
    } else {
        const char *first_colon = strchr(ip_port, ':');
        const char *last_colon  = strrchr(ip_port, ':');
        if ((first_colon != NULL) && (first_colon == last_colon)) {
            size_t hlen = (size_t)(first_colon - ip_port);
            if ((hlen == 0u) || (hlen >= sizeof(host))) return false;
            memcpy(host, ip_port, hlen);
            host[hlen] = '\0';
            if (!parse_port_str(first_colon + 1, &port)) return false;
        } else {
            size_t hlen = strlen(ip_port);
            if ((hlen == 0u) || (hlen >= sizeof(host))) return false;
            memcpy(host, ip_port, hlen + 1u);
        }
    }

    if (port == 0u) return false;
    struct in_addr a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET, host, &a4) == 1) {
        out->fam  = 4u;
        out->port = port;
        memcpy(out->ip, &a4, 4u);
        return true;
    }
    if (inet_pton(AF_INET6, host, &a6) == 1) {
        out->fam  = 6u;
        out->port = port;
        memcpy(out->ip, &a6, 16u);
        return true;
    }
    return false;
}

void ash_ep_to_str(const ash_ep_t *ep, char *buf, size_t cap) {
    if ((buf == NULL) || (cap == 0u)) return;
    if ((ep == NULL) || ((ep->fam != 4u) && (ep->fam != 6u))) {
        snprintf(buf, cap, "<unset>");
        return;
    }
    char ip_str[64] = "?";
    inet_ntop((ep->fam == 4u) ? AF_INET : AF_INET6, ep->ip, ip_str, (socklen_t)sizeof(ip_str));
    if (ep->fam == 4u) {
        snprintf(buf, cap, "%s:%u", ip_str, (unsigned)ep->port);
    } else {
        snprintf(buf, cap, "[%s]:%u", ip_str, (unsigned)ep->port);
    }
}

bool ash_net_init(void) {
#ifdef _WIN32
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
#else
    signal(SIGPIPE, SIG_IGN);
    return true;
#endif
}

void ash_net_cleanup(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

uint64_t ash_now_us(void) {
#ifdef _WIN32
    static LARGE_INTEGER freq;
    LARGE_INTEGER cnt;
    if (freq.QuadPart == 0) {
        QueryPerformanceFrequency(&freq);
    }
    QueryPerformanceCounter(&cnt);
    uint64_t q = (uint64_t)cnt.QuadPart;
    uint64_t f = (uint64_t)freq.QuadPart;
    return (q / f) * 1000000ULL + ((q % f) * 1000000ULL) / f;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000000ULL) + ((uint64_t)ts.tv_nsec / 1000ULL);
#endif
}

uint64_t ash_wall_ms(void) {
#ifdef _WIN32
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    uint64_t ticks = ((uint64_t)ft.dwHighDateTime << 32u) | (uint64_t)ft.dwLowDateTime;
    /* Windows epoch (1601-01-01) to Unix epoch (1970-01-01) in 100-ns intervals */
    const uint64_t epoch_diff = 116444736000000000ULL;
    if (ticks < epoch_diff) return 0ULL;
    return (ticks - epoch_diff) / 10000ULL;
#else
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ((uint64_t)ts.tv_sec * 1000ULL) + ((uint64_t)ts.tv_nsec / 1000000ULL);
#endif
}

bool ash_csprng(void *buf, size_t len) {
    if ((buf == NULL) && (len > 0u)) return false;
    if (len == 0u) return true;
#ifdef _WIN32
    NTSTATUS st = BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return st == 0;
#else
    uint8_t *p = (uint8_t *)buf;
    size_t rem = len;
    while (rem > 0u) {
        ssize_t got = getrandom(p, rem, 0u);
        if (got > 0) {
            p   += (size_t)got;
            rem -= (size_t)got;
        } else if ((got < 0) && (errno == EINTR)) {
            continue;
        } else {
            FILE *f = fopen("/dev/urandom", "rb");
            if (f == NULL) return false;
            size_t rd = fread(p, 1u, rem, f);
            fclose(f);
            return rd == rem;
        }
    }
    return true;
#endif
}

double ash_cpu_seconds(void) {
#ifdef _WIN32
    FILETIME create_ft, exit_ft, kern_ft, user_ft;
    if (!GetProcessTimes(GetCurrentProcess(), &create_ft, &exit_ft, &kern_ft, &user_ft)) {
        return 0.0;
    }
    uint64_t k = ((uint64_t)kern_ft.dwHighDateTime << 32u) | (uint64_t)kern_ft.dwLowDateTime;
    uint64_t u = ((uint64_t)user_ft.dwHighDateTime << 32u) | (uint64_t)user_ft.dwLowDateTime;
    return (double)(k + u) / 1e7;
#else
    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) != 0) return 0.0;
    return (double)ru.ru_utime.tv_sec + ((double)ru.ru_utime.tv_usec / 1e6) +
           (double)ru.ru_stime.tv_sec + ((double)ru.ru_stime.tv_usec / 1e6);
#endif
}

uint64_t ash_rss_bytes(void) {
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS pmc;
    memset(&pmc, 0, sizeof(pmc));
    pmc.cb = sizeof(pmc);
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return (uint64_t)pmc.WorkingSetSize;
    }
    return 0ULL;
#else
    FILE *f = fopen("/proc/self/statm", "r");
    if (f == NULL) return 0ULL;
    char line[128];
    if (fgets(line, (int)sizeof(line), f) == NULL) {
        fclose(f);
        return 0ULL;
    }
    fclose(f);
    char *end1 = NULL;
    char *end2 = NULL;
    (void)strtoul(line, &end1, 10);
    if ((end1 == NULL) || (end1 == line)) return 0ULL;
    unsigned long rss_pages = strtoul(end1, &end2, 10);
    if ((end2 == NULL) || (end2 == end1)) return 0ULL;
    long page_sz = sysconf(_SC_PAGESIZE);
    if (page_sz <= 0) page_sz = 4096;
    return (uint64_t)rss_pages * (uint64_t)page_sz;
#endif
}

uint32_t ash_cpu_count(void) {
#ifdef _WIN32
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return (si.dwNumberOfProcessors > 0u) ? (uint32_t)si.dwNumberOfProcessors : 1u;
#else
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return (n > 0) ? (uint32_t)n : 1u;
#endif
}

void ash_sleep_ms(uint32_t ms) {
#ifdef _WIN32
    Sleep((DWORD)ms);
#else
    struct timespec ts;
    ts.tv_sec  = (time_t)(ms / 1000u);
    ts.tv_nsec = (long)((ms % 1000u) * 1000000u);
    nanosleep(&ts, NULL);
#endif
}

void ash_mutex_init(ash_mutex_t *m) {
#ifdef _WIN32
    InitializeCriticalSectionAndSpinCount(&m->cs, 2000u);
#else
    pthread_mutex_init(&m->mu, NULL);
#endif
}

void ash_mutex_destroy(ash_mutex_t *m) {
#ifdef _WIN32
    DeleteCriticalSection(&m->cs);
#else
    pthread_mutex_destroy(&m->mu);
#endif
}

void ash_mutex_lock(ash_mutex_t *m) {
#ifdef _WIN32
    EnterCriticalSection(&m->cs);
#else
    pthread_mutex_lock(&m->mu);
#endif
}

void ash_mutex_unlock(ash_mutex_t *m) {
#ifdef _WIN32
    LeaveCriticalSection(&m->cs);
#else
    pthread_mutex_unlock(&m->mu);
#endif
}

#ifdef _WIN32
static unsigned __stdcall win_thread_entry(void *p) {
    ash_thread_t *t = (ash_thread_t *)p;
    t->fn(t->arg);
    return 0u;
}
#else
static void *posix_thread_entry(void *p) {
    ash_thread_t *t = (ash_thread_t *)p;
    t->fn(t->arg);
    return NULL;
}
#endif

bool ash_thread_start(ash_thread_t *t, ash_thread_fn fn, void *arg, int pin_core) {
    if ((t == NULL) || (fn == NULL)) return false;
    t->fn  = fn;
    t->arg = arg;
#ifdef _WIN32
    uintptr_t h = _beginthreadex(NULL, 0u, win_thread_entry, t, 0u, NULL);
    if (h == 0u) return false;
    t->h = (HANDLE)h;
    if ((pin_core >= 0) && (pin_core < 64)) {
        DWORD_PTR mask = ((DWORD_PTR)1u) << (unsigned)pin_core;
        SetThreadAffinityMask(t->h, mask);
    }
    return true;
#else
    if (pthread_create(&t->th, NULL, posix_thread_entry, t) != 0) {
        return false;
    }
#ifdef __linux__
    if ((pin_core >= 0) && (pin_core < CPU_SETSIZE)) {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET((size_t)pin_core, &cpuset);
        (void)pthread_setaffinity_np(t->th, sizeof(cpuset), &cpuset);
    }
#else
    (void)pin_core;
#endif
    return true;
#endif
}

void ash_thread_join(ash_thread_t *t) {
    if (t == NULL) return;
#ifdef _WIN32
    if (t->h != NULL) {
        WaitForSingleObject(t->h, INFINITE);
        CloseHandle(t->h);
        t->h = NULL;
    }
#else
    pthread_join(t->th, NULL);
#endif
}

bool ash_sock_set_nonblock(ash_sock_t s) {
    if (s == ASH_INVALID_SOCK) return false;
#ifdef _WIN32
    u_long nb = 1ul;
    return ioctlsocket(s, (long)FIONBIO, &nb) == 0;
#else
    int flags = fcntl(s, F_GETFL, 0);
    if (flags < 0) return false;
    return fcntl(s, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

static bool fill_bind_sa6(const char *bind_ip, uint16_t port, struct sockaddr_in6 *sa6) {
    memset(sa6, 0, sizeof(*sa6));
    sa6->sin6_family = AF_INET6;
    sa6->sin6_port   = htons(port);
    if ((bind_ip == NULL) || (bind_ip[0] == '\0') ||
        (strcmp(bind_ip, "::") == 0) || (strcmp(bind_ip, "0.0.0.0") == 0)) {
        sa6->sin6_addr = in6addr_any;
        return true;
    }
    if (inet_pton(AF_INET6, bind_ip, &sa6->sin6_addr) == 1) {
        return true;
    }
    struct in_addr a4;
    if (inet_pton(AF_INET, bind_ip, &a4) == 1) {
        uint8_t *dst = (uint8_t *)&sa6->sin6_addr;
        memcpy(dst, k_v4mapped_prefix, 12u);
        memcpy(dst + 12u, &a4, 4u);
        return true;
    }
    return false;
}

ash_sock_t ash_udp_bind(const char *bind_ip, uint16_t port, bool reuse_port, int buf_bytes) {
    ash_sock_t s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (s == ASH_INVALID_SOCK) return ASH_INVALID_SOCK;

    int v6only = 0;
    (void)setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&v6only, sizeof(v6only));

    if (reuse_port) {
#ifdef SO_REUSEPORT
        int one = 1;
        (void)setsockopt(s, SOL_SOCKET, SO_REUSEPORT, (const char *)&one, sizeof(one));
#else
        int one = 1;
        (void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof(one));
#endif
    }

    if (buf_bytes > 0) {
        (void)setsockopt(s, SOL_SOCKET, SO_RCVBUF, (const char *)&buf_bytes, sizeof(buf_bytes));
        (void)setsockopt(s, SOL_SOCKET, SO_SNDBUF, (const char *)&buf_bytes, sizeof(buf_bytes));
    }

#ifdef _WIN32
    BOOL no_reset = FALSE;
    DWORD ret_bytes = 0u;
    (void)WSAIoctl(s, SIO_UDP_CONNRESET, &no_reset, sizeof(no_reset),
                   NULL, 0u, &ret_bytes, NULL, NULL);
#endif

    struct sockaddr_in6 sa6;
    if (!fill_bind_sa6(bind_ip, port, &sa6) ||
        (bind(s, (const struct sockaddr *)&sa6, (socklen_t)sizeof(sa6)) != 0) ||
        !ash_sock_set_nonblock(s)) {
        ash_sock_close(s);
        return ASH_INVALID_SOCK;
    }
    return s;
}

ash_sock_t ash_tcp_listen(const char *bind_ip, uint16_t port, bool reuse_port, int backlog) {
    ash_sock_t s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (s == ASH_INVALID_SOCK) return ASH_INVALID_SOCK;

    int v6only = 0;
    (void)setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&v6only, sizeof(v6only));

#ifndef _WIN32
    int reuse_addr = 1;
    (void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse_addr, sizeof(reuse_addr));
#endif
    if (reuse_port) {
#ifdef SO_REUSEPORT
        int one = 1;
        (void)setsockopt(s, SOL_SOCKET, SO_REUSEPORT, (const char *)&one, sizeof(one));
#endif
    }

    struct sockaddr_in6 sa6;
    int bl = (backlog > 0) ? backlog : 1024;
    if (!fill_bind_sa6(bind_ip, port, &sa6) ||
        (bind(s, (const struct sockaddr *)&sa6, (socklen_t)sizeof(sa6)) != 0) ||
        (listen(s, bl) != 0) ||
        !ash_sock_set_nonblock(s)) {
        ash_sock_close(s);
        return ASH_INVALID_SOCK;
    }
    return s;
}

bool ash_tcp_tune_accepted(ash_sock_t s, int sndbuf_bytes) {
    if (s == ASH_INVALID_SOCK) return false;
    int nodelay = 1;
    (void)setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&nodelay, sizeof(nodelay));
    int keepalive = 1;
    (void)setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (const char *)&keepalive, sizeof(keepalive));
    if (sndbuf_bytes > 0) {
        (void)setsockopt(s, SOL_SOCKET, SO_SNDBUF, (const char *)&sndbuf_bytes, sizeof(sndbuf_bytes));
    }
    return ash_sock_set_nonblock(s);
}

uint16_t ash_sock_bound_port(ash_sock_t s) {
    if (s == ASH_INVALID_SOCK) return 0u;
    struct sockaddr_storage ss;
    socklen_t sl = (socklen_t)sizeof(ss);
    memset(&ss, 0, sizeof(ss));
    if (getsockname(s, (struct sockaddr *)&ss, &sl) != 0) return 0u;
    if (ss.ss_family == AF_INET) {
        return ntohs(((const struct sockaddr_in *)&ss)->sin_port);
    }
    if (ss.ss_family == AF_INET6) {
        return ntohs(((const struct sockaddr_in6 *)&ss)->sin6_port);
    }
    return 0u;
}

void ash_sock_close(ash_sock_t s) {
    if (s == ASH_INVALID_SOCK) return;
#ifdef _WIN32
    closesocket(s);
#else
    close(s);
#endif
}
