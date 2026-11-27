#ifndef ASH_RATELIMIT_H
#define ASH_RATELIMIT_H

#include "ash_common.h"
#include "ash_wire.h"

#ifdef __cplusplus
extern "C" {
#endif

/* High-precision byte token bucket (drift-free microsecond replenishment) */
typedef struct {
    uint32_t rate_kbps;    /* 0 = unlimited */
    uint64_t burst_bytes;
    uint64_t tokens_bytes;
    uint64_t last_us;
} ash_tb_t;

void ash_tb_init(ash_tb_t *tb, uint32_t rate_kbps, uint32_t burst_ms);
void ash_tb_reconfig(ash_tb_t *tb, uint32_t rate_kbps, uint32_t burst_ms);
bool ash_tb_consume(ash_tb_t *tb, size_t bytes, uint64_t now_us);

/* Stateless rotating HMAC cookie generator/verifier (zero per-client state) */
typedef struct {
    ash_mutex_t mu;
    uint8_t     secret_cur[32];
    uint8_t     secret_prev[32];
    uint64_t    rotated_us;
    uint64_t    rotate_iv_us;
} ash_cookie_jar_t;

bool ash_cookie_jar_init(ash_cookie_jar_t *jar, uint64_t rotate_iv_us);
void ash_cookie_jar_destroy(ash_cookie_jar_t *jar);
void ash_cookie_make(ash_cookie_jar_t *jar, const ash_ep_t *src, uint64_t now_us,
                     uint8_t out_cookie[ASH_COOKIE_LEN]);
bool ash_cookie_check(ash_cookie_jar_t *jar, const ash_ep_t *src, uint64_t now_us,
                      const uint8_t cookie[ASH_COOKIE_LEN]);

/* Sharded 4-way set-associative per-IPv4 / IPv6-/64 rate & penalty limiter */
#define ASH_GUARD_SHARDS 64u
#define ASH_GUARD_WAYS   4u

typedef struct {
    uint64_t tag;            /* Non-zero SipHash tag of IPv4 or IPv6 /64 prefix */
    uint64_t window_us;      /* Start of 1-second signaling rate window */
    uint64_t block_until_us; /* Temporary penalty block expiration */
    uint16_t sig_count;      /* Signaling packets in current 1s window */
    uint16_t strikes;        /* Bad token / bad signature strikes */
    uint16_t pin_day;        /* Day the pins below were counted in */
    uint16_t pins;           /* AshDesk numbers newly pinned by this source that day */
} ash_ip_slot_t;

typedef struct {
    ash_ip_slot_t ways[ASH_GUARD_WAYS];
} ash_ip_set_t;

typedef struct {
    ash_mutex_t   mu;
    ash_ip_set_t *sets;
    uint32_t      set_mask;
    uint8_t       cache_pad[ASH_CACHELINE_PAD];
} ash_guard_shard_t;

typedef struct {
    uint8_t           sip_key[16];
    uint16_t          max_sig_per_sec;
    uint16_t          max_strikes;
    uint16_t          max_pins_per_day;  /* 0 = no allowance check; set after init */
    uint64_t          penalty_us;
    ash_guard_shard_t shards[ASH_GUARD_SHARDS];
    ash_atomic_u64    dropped_rate;
    ash_atomic_u64    dropped_penalty;
} ash_ip_guard_t;

bool ash_ip_guard_init(ash_ip_guard_t *g, uint32_t total_sets_pow2,
                       uint16_t max_sig_per_sec, uint16_t max_strikes, uint64_t penalty_us);
void ash_ip_guard_destroy(ash_ip_guard_t *g);
bool ash_ip_guard_allow_sig(ash_ip_guard_t *g, const ash_ep_t *src, uint64_t now_us);
bool ash_ip_guard_is_blocked(ash_ip_guard_t *g, const ash_ep_t *src, uint64_t now_us);
void ash_ip_guard_add_strike(ash_ip_guard_t *g, const ash_ep_t *src, uint64_t now_us);
/* Daily allowance of newly pinned AshDesk numbers per source: keeps one subscriber from filling the registry and the
 * append-only keystore. A source is an IPv4 address or an IPv6 /48 — wider than the /64 the rate limit uses, because a
 * subscriber is usually handed a whole /56 or /48 and every /64 in it would otherwise be a fresh allowance.
 * may_pin peeks, note_pin counts one; `day` is any counter that changes once a day. Numbers the source already owns
 * never go through this. */
bool ash_ip_guard_may_pin(ash_ip_guard_t *g, const ash_ep_t *src, uint64_t now_us, uint16_t day);
void ash_ip_guard_note_pin(ash_ip_guard_t *g, const ash_ep_t *src, uint64_t now_us, uint16_t day);
size_t ash_ip_guard_memory_bytes(const ash_ip_guard_t *g);

#ifdef __cplusplus
}
#endif

#endif /* ASH_RATELIMIT_H */
