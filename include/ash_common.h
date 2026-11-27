#ifndef ASH_COMMON_H
#define ASH_COMMON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET ash_sock_t;
typedef int    ash_io_len_t;
#define ASH_INVALID_SOCK INVALID_SOCKET
#else
#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>
typedef int    ash_sock_t;
typedef size_t ash_io_len_t;
#define ASH_INVALID_SOCK (-1)
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Cache-line separation padding size to eliminate false sharing across shards */
#define ASH_CACHELINE_PAD 64u

/* Portable 64-bit atomics (compatible with C17 MSVC, C++17 GoogleTest, and POSIX TSan) */
#if defined(_MSC_VER)
typedef struct {
    volatile LONG64 v;
} ash_atomic_u64;

static inline void ash_atomic_init(ash_atomic_u64 *a, uint64_t val) {
    InterlockedExchange64(&a->v, (LONG64)val);
}
static inline uint64_t ash_atomic_load(const ash_atomic_u64 *a) {
    return (uint64_t)InterlockedCompareExchange64((volatile LONG64 *)&a->v, 0, 0);
}
static inline void ash_atomic_store(ash_atomic_u64 *a, uint64_t val) {
    InterlockedExchange64(&a->v, (LONG64)val);
}
static inline uint64_t ash_atomic_add(ash_atomic_u64 *a, uint64_t delta) {
    return (uint64_t)InterlockedExchangeAdd64(&a->v, (LONG64)delta) + delta;
}
static inline uint64_t ash_atomic_inc(ash_atomic_u64 *a) {
    return (uint64_t)InterlockedIncrement64(&a->v);
}
#elif defined(__cplusplus)
#include <atomic>
typedef struct {
    std::atomic<uint64_t> v;
} ash_atomic_u64;

static inline void ash_atomic_init(ash_atomic_u64 *a, uint64_t val) {
    a->v.store(val, std::memory_order_relaxed);
}
static inline uint64_t ash_atomic_load(const ash_atomic_u64 *a) {
    return a->v.load(std::memory_order_acquire);
}
static inline void ash_atomic_store(ash_atomic_u64 *a, uint64_t val) {
    a->v.store(val, std::memory_order_release);
}
static inline uint64_t ash_atomic_add(ash_atomic_u64 *a, uint64_t delta) {
    return a->v.fetch_add(delta, std::memory_order_relaxed) + delta;
}
static inline uint64_t ash_atomic_inc(ash_atomic_u64 *a) {
    return a->v.fetch_add(1ULL, std::memory_order_relaxed) + 1ULL;
}
#else
#include <stdatomic.h>
typedef struct {
    _Atomic uint64_t v;
} ash_atomic_u64;

static inline void ash_atomic_init(ash_atomic_u64 *a, uint64_t val) {
    atomic_init(&a->v, val);
}
static inline uint64_t ash_atomic_load(const ash_atomic_u64 *a) {
    return atomic_load_explicit(&a->v, memory_order_acquire);
}
static inline void ash_atomic_store(ash_atomic_u64 *a, uint64_t val) {
    atomic_store_explicit(&a->v, val, memory_order_release);
}
static inline uint64_t ash_atomic_add(ash_atomic_u64 *a, uint64_t delta) {
    return atomic_fetch_add_explicit(&a->v, delta, memory_order_relaxed) + delta;
}
static inline uint64_t ash_atomic_inc(ash_atomic_u64 *a) {
    return atomic_fetch_add_explicit(&a->v, 1ULL, memory_order_relaxed) + 1ULL;
}
#endif

/* Unaligned-safe endian helpers */
static inline uint16_t ash_get_be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8u) | (uint16_t)p[1]);
}

static inline void ash_put_be16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8u);
    p[1] = (uint8_t)(v & 0xFFu);
}

static inline uint32_t ash_get_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24u) | ((uint32_t)p[1] << 16u) |
           ((uint32_t)p[2] << 8u) | (uint32_t)p[3];
}

static inline void ash_put_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24u);
    p[1] = (uint8_t)(v >> 16u);
    p[2] = (uint8_t)(v >> 8u);
    p[3] = (uint8_t)(v & 0xFFu);
}

static inline uint64_t ash_get_be64(const uint8_t *p) {
    return ((uint64_t)ash_get_be32(p) << 32u) | (uint64_t)ash_get_be32(p + 4);
}

static inline void ash_put_be64(uint8_t *p, uint64_t v) {
    ash_put_be32(p, (uint32_t)(v >> 32u));
    ash_put_be32(p + 4, (uint32_t)(v & 0xFFFFFFFFu));
}

static inline uint64_t ash_get_le64(const uint8_t *p) {
    return ((uint64_t)p[0]) |
           ((uint64_t)p[1] << 8u) |
           ((uint64_t)p[2] << 16u) |
           ((uint64_t)p[3] << 24u) |
           ((uint64_t)p[4] << 32u) |
           ((uint64_t)p[5] << 40u) |
           ((uint64_t)p[6] << 48u) |
           ((uint64_t)p[7] << 56u);
}

static inline void ash_put_le64(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8u) & 0xFFu);
    p[2] = (uint8_t)((v >> 16u) & 0xFFu);
    p[3] = (uint8_t)((v >> 24u) & 0xFFu);
    p[4] = (uint8_t)((v >> 32u) & 0xFFu);
    p[5] = (uint8_t)((v >> 40u) & 0xFFu);
    p[6] = (uint8_t)((v >> 48u) & 0xFFu);
    p[7] = (uint8_t)((v >> 56u) & 0xFFu);
}

/* Normalized IPv4/IPv6 network endpoint (20 bytes, zero internal padding) */
typedef struct {
    uint8_t  fam;     /* 4 = IPv4 (ip[0..3]), 6 = IPv6 (ip[0..15]), 0 = unset */
    uint8_t  proto;   /* 0/17 = UDP, 6 = TCP */
    uint16_t port;    /* Host byte order */
    uint8_t  ip[16];
} ash_ep_t;

bool ash_ep_eq(const ash_ep_t *a, const ash_ep_t *b);
bool ash_ep_same_ip(const ash_ep_t *a, const ash_ep_t *b);
bool ash_ep_is_private(const ash_ep_t *ep);
void      ash_ep_from_sockaddr(const struct sockaddr_storage *ss, uint8_t proto, ash_ep_t *out);
socklen_t ash_ep_to_sockaddr6(const ash_ep_t *ep, struct sockaddr_in6 *sa6);
bool ash_ep_parse(const char *ip_port, uint16_t default_port, ash_ep_t *out);
void ash_ep_to_str(const ash_ep_t *ep, char *buf, size_t cap);

/* Platform lifecycle, clocks, CSPRNG, telemetry */
bool     ash_net_init(void);
void     ash_net_cleanup(void);
uint64_t ash_now_us(void);
uint64_t ash_wall_ms(void);
bool     ash_csprng(void *buf, size_t len);
double   ash_cpu_seconds(void);
uint64_t ash_rss_bytes(void);
uint32_t ash_cpu_count(void);
void     ash_sleep_ms(uint32_t ms);

/* Cross-platform lightweight mutex & worker threads */
typedef struct {
#ifdef _WIN32
    CRITICAL_SECTION cs;
#else
    pthread_mutex_t mu;
#endif
} ash_mutex_t;

void ash_mutex_init(ash_mutex_t *m);
void ash_mutex_destroy(ash_mutex_t *m);
void ash_mutex_lock(ash_mutex_t *m);
void ash_mutex_unlock(ash_mutex_t *m);

typedef void (*ash_thread_fn)(void *arg);

typedef struct {
#ifdef _WIN32
    HANDLE h;
#else
    pthread_t th;
#endif
    ash_thread_fn fn;
    void         *arg;
} ash_thread_t;

bool ash_thread_start(ash_thread_t *t, ash_thread_fn fn, void *arg, int pin_core);
void ash_thread_join(ash_thread_t *t);

/* Dual-stack non-blocking socket helpers */
ash_sock_t ash_udp_bind(const char *bind_ip, uint16_t port, bool reuse_port, int buf_bytes);
ash_sock_t ash_tcp_listen(const char *bind_ip, uint16_t port, bool reuse_port, int backlog);
bool       ash_sock_set_nonblock(ash_sock_t s);
bool       ash_tcp_tune_accepted(ash_sock_t s, int sndbuf_bytes);
uint16_t   ash_sock_bound_port(ash_sock_t s);
void       ash_sock_close(ash_sock_t s);

#ifdef __cplusplus
}
#endif

#endif /* ASH_COMMON_H */
