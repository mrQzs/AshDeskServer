#include "ash_ratelimit.h"
#include "ash_crypto.h"

#include <stdlib.h>
#include <string.h>

void ash_tb_init(ash_tb_t *tb, uint32_t rate_kbps, uint32_t burst_ms) {
    if (tb == NULL) return;
    memset(tb, 0, sizeof(*tb));
    ash_tb_reconfig(tb, rate_kbps, burst_ms);
}

void ash_tb_reconfig(ash_tb_t *tb, uint32_t rate_kbps, uint32_t burst_ms) {
    if (tb == NULL) return;
    tb->rate_kbps = rate_kbps;
    if (rate_kbps == 0u) {
        tb->burst_bytes  = 0ULL;
        tb->tokens_bytes = 0ULL;
        return;
    }
    uint32_t ms = (burst_ms != 0u) ? burst_ms : 100u;
    uint64_t burst = ((uint64_t)rate_kbps * (uint64_t)ms) / 8ULL;
    if (burst < 4096ULL) {
        burst = 4096ULL;
    }
    tb->burst_bytes = burst;
    if ((tb->last_us == 0ULL) || (tb->tokens_bytes > burst)) {
        tb->tokens_bytes = burst;
    }
}

bool ash_tb_consume(ash_tb_t *tb, size_t bytes, uint64_t now_us) {
    if (tb == NULL) return false;
    if (tb->rate_kbps == 0u) return true;

    if (tb->last_us == 0ULL) {
        tb->last_us = now_us;
    } else if (now_us > tb->last_us) {
        uint64_t dt_us = now_us - tb->last_us;
        uint64_t r64   = (uint64_t)tb->rate_kbps;
        /* Guard multiplication overflow on long idle intervals (> 10 s saturates bucket) */
        if (dt_us >= 10000000ULL) {
            tb->tokens_bytes = tb->burst_bytes;
            tb->last_us      = now_us;
        } else {
            uint64_t add = (dt_us * r64) / 8000ULL;
            if (add > 0ULL) {
                if ((tb->tokens_bytes + add) >= tb->burst_bytes) {
                    tb->tokens_bytes = tb->burst_bytes;
                    tb->last_us      = now_us;
                } else {
                    tb->tokens_bytes += add;
                    tb->last_us      += (add * 8000ULL) / r64;
                }
            }
        }
    }

    uint64_t need = (uint64_t)bytes;
    if (tb->tokens_bytes >= need) {
        tb->tokens_bytes -= need;
        return true;
    }
    return false;
}

/* ---------------- Stateless Rotating Cookie Jar ---------------- */
bool ash_cookie_jar_init(ash_cookie_jar_t *jar, uint64_t rotate_iv_us) {
    if (jar == NULL) return false;
    memset(jar, 0, sizeof(*jar));
    ash_mutex_init(&jar->mu);
    if (!ash_csprng(jar->secret_cur, sizeof(jar->secret_cur)) ||
        !ash_csprng(jar->secret_prev, sizeof(jar->secret_prev))) {
        ash_mutex_destroy(&jar->mu);
        return false;
    }
    jar->rotated_us   = ash_now_us();
    jar->rotate_iv_us = (rotate_iv_us > 0ULL) ? rotate_iv_us : 30000000ULL;
    return true;
}

void ash_cookie_jar_destroy(ash_cookie_jar_t *jar) {
    if (jar == NULL) return;
    ash_mutex_destroy(&jar->mu);
    ash_secure_zero(jar, sizeof(*jar));
}

static void cookie_compute_key(const uint8_t secret[32], const ash_ep_t *src,
                               uint8_t out_cookie[ASH_COOKIE_LEN]) {
    uint8_t buf[20];
    buf[0] = src->fam;
    buf[1] = src->proto;
    ash_put_be16(buf + 2u, src->port);
    memcpy(buf + 4u, src->ip, 16u);
    uint8_t mac[ASH_SHA256_BYTES];
    ash_hmac_sha256(secret, 32u, buf, sizeof(buf), mac);
    memcpy(out_cookie, mac, ASH_COOKIE_LEN);
    ash_secure_zero(mac, sizeof(mac));
}

static void jar_maybe_rotate_locked(ash_cookie_jar_t *jar, uint64_t now_us) {
    if ((now_us > jar->rotated_us) && ((now_us - jar->rotated_us) >= jar->rotate_iv_us)) {
        memcpy(jar->secret_prev, jar->secret_cur, 32u);
        (void)ash_csprng(jar->secret_cur, 32u);
        jar->rotated_us = now_us;
    }
}

void ash_cookie_make(ash_cookie_jar_t *jar, const ash_ep_t *src, uint64_t now_us,
                     uint8_t out_cookie[ASH_COOKIE_LEN]) {
    uint8_t cur[32];
    ash_mutex_lock(&jar->mu);
    jar_maybe_rotate_locked(jar, now_us);
    memcpy(cur, jar->secret_cur, 32u);
    ash_mutex_unlock(&jar->mu);

    cookie_compute_key(cur, src, out_cookie);
    ash_secure_zero(cur, sizeof(cur));
}

bool ash_cookie_check(ash_cookie_jar_t *jar, const ash_ep_t *src, uint64_t now_us,
                      const uint8_t cookie[ASH_COOKIE_LEN]) {
    if ((jar == NULL) || (src == NULL) || (cookie == NULL)) return false;
    uint8_t cur[32], prev[32];
    ash_mutex_lock(&jar->mu);
    jar_maybe_rotate_locked(jar, now_us);
    memcpy(cur, jar->secret_cur, 32u);
    memcpy(prev, jar->secret_prev, 32u);
    ash_mutex_unlock(&jar->mu);

    uint8_t expect[ASH_COOKIE_LEN];
    cookie_compute_key(cur, src, expect);
    bool ok = ash_ct_equal(expect, cookie, ASH_COOKIE_LEN);
    if (!ok) {
        cookie_compute_key(prev, src, expect);
        ok = ash_ct_equal(expect, cookie, ASH_COOKIE_LEN);
    }
    ash_secure_zero(cur, sizeof(cur));
    ash_secure_zero(prev, sizeof(prev));
    ash_secure_zero(expect, sizeof(expect));
    return ok;
}

/* ---------------- Sharded Per-IP / IPv6-/64 Limiter ---------------- */
#define V6_SUBNET 8u /* /64: rate and penalty, defeats interface-ID rotation */
#define V6_SITE   6u /* /48: the new-number allowance; a subscriber usually holds a whole /56 or /48, so another
                      * subnet must not be another allowance */

static uint64_t hash_ip_prefix(const uint8_t sip_key[16], const ash_ep_t *src, size_t v6_len) {
    uint8_t key_bytes[9];
    size_t klen = 0u;
    key_bytes[0] = src->fam;
    if (src->fam == 4u) {
        memcpy(key_bytes + 1u, src->ip, 4u);
        klen = 5u;
    } else {
        if (v6_len == V6_SITE) key_bytes[0] = 48u; /* Never the tag of the /64 whose subnet bits are zero */
        memcpy(key_bytes + 1u, src->ip, v6_len);
        klen = 1u + v6_len;
    }
    uint64_t h = ash_siphash24(sip_key, key_bytes, klen);
    return (h != 0ULL) ? h : 1ULL;
}

static uint32_t round_pow2_u32(uint32_t v) {
    uint32_t p = 16u;
    while ((p < v) && (p < (1u << 24u))) {
        p <<= 1u;
    }
    return p;
}

bool ash_ip_guard_init(ash_ip_guard_t *g, uint32_t total_sets_pow2,
                       uint16_t max_sig_per_sec, uint16_t max_strikes, uint64_t penalty_us) {
    if (g == NULL) return false;
    memset(g, 0, sizeof(*g));
    if (!ash_csprng(g->sip_key, sizeof(g->sip_key))) return false;

    uint32_t per_shard = total_sets_pow2 / ASH_GUARD_SHARDS;
    if (per_shard < 16u) per_shard = 16u;
    per_shard = round_pow2_u32(per_shard);

    g->max_sig_per_sec = (max_sig_per_sec > 0u) ? max_sig_per_sec : 60u;
    g->max_strikes     = (max_strikes > 0u) ? max_strikes : 12u;
    g->penalty_us      = (penalty_us > 0ULL) ? penalty_us : 10000000ULL;
    ash_atomic_init(&g->dropped_rate, 0ULL);
    ash_atomic_init(&g->dropped_penalty, 0ULL);

    for (uint32_t i = 0u; i < ASH_GUARD_SHARDS; ++i) {
        ash_mutex_init(&g->shards[i].mu);
        g->shards[i].set_mask = per_shard - 1u;
        g->shards[i].sets = (ash_ip_set_t *)calloc(per_shard, sizeof(ash_ip_set_t));
        if (g->shards[i].sets == NULL) {
            for (uint32_t j = 0u; j <= i; ++j) {
                free(g->shards[j].sets);
                g->shards[j].sets = NULL;
                ash_mutex_destroy(&g->shards[j].mu);
            }
            return false;
        }
    }
    return true;
}

void ash_ip_guard_destroy(ash_ip_guard_t *g) {
    if (g == NULL) return;
    for (uint32_t i = 0u; i < ASH_GUARD_SHARDS; ++i) {
        if (g->shards[i].sets != NULL) {
            free(g->shards[i].sets);
            g->shards[i].sets = NULL;
        }
        ash_mutex_destroy(&g->shards[i].mu);
    }
}

static ash_ip_slot_t *find_or_alloc_slot(ash_ip_set_t *set, uint64_t tag, uint64_t now_us) {
    size_t oldest_idx = 0u;
    uint64_t oldest_t = UINT64_MAX;
    for (size_t w = 0u; w < ASH_GUARD_WAYS; ++w) {
        ash_ip_slot_t *sl = &set->ways[w];
        if (sl->tag == tag) return sl;
        if (sl->tag == 0ULL) {
            memset(sl, 0, sizeof(*sl));
            sl->tag       = tag;
            sl->window_us = now_us;
            return sl;
        }
        /* Prefer evicting non-penalized older entries */
        uint64_t score = (sl->block_until_us > now_us) ? (sl->block_until_us + 60000000ULL) : sl->window_us;
        if (score < oldest_t) {
            oldest_t   = score;
            oldest_idx = w;
        }
    }
    ash_ip_slot_t *ev = &set->ways[oldest_idx];
    memset(ev, 0, sizeof(*ev));
    ev->tag       = tag;
    ev->window_us = now_us;
    return ev;
}

bool ash_ip_guard_allow_sig(ash_ip_guard_t *g, const ash_ep_t *src, uint64_t now_us) {
    uint64_t tag = hash_ip_prefix(g->sip_key, src, V6_SUBNET);
    uint32_t sidx = (uint32_t)(tag & (ASH_GUARD_SHARDS - 1u));
    ash_guard_shard_t *sh = &g->shards[sidx];

    ash_mutex_lock(&sh->mu);
    ash_ip_set_t *set = &sh->sets[(uint32_t)(tag >> 6u) & sh->set_mask];
    ash_ip_slot_t *sl = find_or_alloc_slot(set, tag, now_us);

    if (sl->block_until_us > now_us) {
        ash_mutex_unlock(&sh->mu);
        (void)ash_atomic_inc(&g->dropped_penalty);
        return false;
    }

    if ((now_us < sl->window_us) || ((now_us - sl->window_us) >= 1000000ULL)) {
        sl->window_us = now_us;
        sl->sig_count = 1u;
        if (sl->strikes > 0u) sl->strikes = (uint16_t)(sl->strikes - 1u);
        ash_mutex_unlock(&sh->mu);
        return true;
    }

    if (sl->sig_count >= g->max_sig_per_sec) {
        ash_mutex_unlock(&sh->mu);
        (void)ash_atomic_inc(&g->dropped_rate);
        return false;
    }
    sl->sig_count += 1u;
    ash_mutex_unlock(&sh->mu);
    return true;
}

/* Caller holds the shard lock. An IPv4 source counts its pins in the slot its signaling uses; an IPv6 /48 has a slot of
 * its own that no signaling refreshes, so asking keeps it from looking idle to eviction. */
static ash_ip_slot_t *pin_slot(ash_guard_shard_t *sh, uint64_t tag, const ash_ep_t *src, uint64_t now_us, uint16_t day) {
    ash_ip_set_t *set = &sh->sets[(uint32_t)(tag >> 6u) & sh->set_mask];
    ash_ip_slot_t *sl = find_or_alloc_slot(set, tag, now_us);
    if (src->fam != 4u) sl->window_us = now_us;
    if (sl->pin_day != day) {
        sl->pin_day = day;
        sl->pins    = 0u;
    }
    return sl;
}

bool ash_ip_guard_may_pin(ash_ip_guard_t *g, const ash_ep_t *src, uint64_t now_us, uint16_t day) {
    if (g->max_pins_per_day == 0u) return true;
    uint64_t tag = hash_ip_prefix(g->sip_key, src, V6_SITE);
    ash_guard_shard_t *sh = &g->shards[(uint32_t)(tag & (ASH_GUARD_SHARDS - 1u))];
    ash_mutex_lock(&sh->mu);
    bool ok = pin_slot(sh, tag, src, now_us, day)->pins < g->max_pins_per_day;
    ash_mutex_unlock(&sh->mu);
    return ok;
}

void ash_ip_guard_note_pin(ash_ip_guard_t *g, const ash_ep_t *src, uint64_t now_us, uint16_t day) {
    if (g->max_pins_per_day == 0u) return;
    uint64_t tag = hash_ip_prefix(g->sip_key, src, V6_SITE);
    ash_guard_shard_t *sh = &g->shards[(uint32_t)(tag & (ASH_GUARD_SHARDS - 1u))];
    ash_mutex_lock(&sh->mu);
    ash_ip_slot_t *sl = pin_slot(sh, tag, src, now_us, day);
    if (sl->pins < UINT16_MAX) {
        sl->pins = (uint16_t)(sl->pins + 1u);
    }
    ash_mutex_unlock(&sh->mu);
}

bool ash_ip_guard_is_blocked(ash_ip_guard_t *g, const ash_ep_t *src, uint64_t now_us) {
    uint64_t tag = hash_ip_prefix(g->sip_key, src, V6_SUBNET);
    uint32_t sidx = (uint32_t)(tag & (ASH_GUARD_SHARDS - 1u));
    ash_guard_shard_t *sh = &g->shards[sidx];

    ash_mutex_lock(&sh->mu);
    ash_ip_set_t *set = &sh->sets[(uint32_t)(tag >> 6u) & sh->set_mask];
    bool blocked = false;
    for (size_t w = 0u; w < ASH_GUARD_WAYS; ++w) {
        if (set->ways[w].tag == tag) {
            blocked = (set->ways[w].block_until_us > now_us);
            break;
        }
    }
    ash_mutex_unlock(&sh->mu);
    if (blocked) {
        (void)ash_atomic_inc(&g->dropped_penalty);
    }
    return blocked;
}

void ash_ip_guard_add_strike(ash_ip_guard_t *g, const ash_ep_t *src, uint64_t now_us) {
    uint64_t tag = hash_ip_prefix(g->sip_key, src, V6_SUBNET);
    uint32_t sidx = (uint32_t)(tag & (ASH_GUARD_SHARDS - 1u));
    ash_guard_shard_t *sh = &g->shards[sidx];

    ash_mutex_lock(&sh->mu);
    ash_ip_set_t *set = &sh->sets[(uint32_t)(tag >> 6u) & sh->set_mask];
    ash_ip_slot_t *sl = find_or_alloc_slot(set, tag, now_us);
    if (sl->strikes < UINT16_MAX) {
        sl->strikes += 1u;
    }
    if (sl->strikes >= g->max_strikes) {
        sl->block_until_us = now_us + g->penalty_us;
        sl->strikes        = 0u;
    }
    ash_mutex_unlock(&sh->mu);
}

size_t ash_ip_guard_memory_bytes(const ash_ip_guard_t *g) {
    if (g == NULL) return 0u;
    size_t per_shard = (size_t)(g->shards[0].set_mask + 1u) * sizeof(ash_ip_set_t);
    return sizeof(*g) + ((size_t)ASH_GUARD_SHARDS * per_shard);
}
