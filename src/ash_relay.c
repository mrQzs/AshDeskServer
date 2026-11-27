#include "ash_relay.h"

#include <stdlib.h>
#include <string.h>

static uint32_t pow2_ceil_u32(uint32_t v) {
    uint32_t p = 16u;
    while ((p < v) && (p < (1u << 24u))) {
        p <<= 1u;
    }
    return p;
}

static bool sess_alive(const ash_relay_sess_t *s, uint64_t now_us, uint64_t ttl_us) {
    if (s->sess == 0u) return false;
    if (now_us <= s->last_seen_us) return true;
    return (now_us - s->last_seen_us) < ttl_us;
}

static ash_relay_sess_t *shard_find_sess(ash_relay_shard_t *sh,
                                         uint32_t sess,
                                         uint64_t now_us,
                                         uint64_t ttl_us,
                                         ash_relay_sess_t **out_free) {
    uint32_t start = (sess >> 6u) & sh->mask;
    ash_relay_sess_t *free_slot = NULL;
    for (uint32_t p = 0u; p < sh->cap; ++p) {
        ash_relay_sess_t *s = &sh->slots[(start + p) & sh->mask];
        if (s->sess == 0u) {
            if (free_slot == NULL) free_slot = s;
            break;
        }
        if (s->sess == sess) {
            if (sess_alive(s, now_us, ttl_us)) {
                return s;
            }
            if (free_slot == NULL) free_slot = s;
        } else if (!sess_alive(s, now_us, ttl_us)) {
            if (free_slot == NULL) free_slot = s;
        }
    }
    if (out_free != NULL) *out_free = free_slot;
    return NULL;
}

static ash_relay_sess_t *shard_alloc_sess(ash_relay_shard_t *sh,
                                          uint32_t sess,
                                          uint64_t now_us,
                                          uint64_t ttl_us) {
    uint32_t start = (sess >> 6u) & sh->mask;
    for (uint32_t p = 0u; p < sh->cap; ++p) {
        ash_relay_sess_t *s = &sh->slots[(start + p) & sh->mask];
        if ((s->sess == 0u) || !sess_alive(s, now_us, ttl_us)) {
            memset(s, 0, sizeof(*s));
            s->sess = sess;
            return s;
        }
    }
    return NULL;
}

bool ash_relay_init(ash_relay_table_t *rt, uint32_t max_sessions, const ash_relay_cfg_t *cfg) {
    if ((rt == NULL) || (cfg == NULL)) return false;
    memset(rt, 0, sizeof(*rt));
    rt->cfg = *cfg;
    if (rt->cfg.sess_ttl_us == 0ULL) rt->cfg.sess_ttl_us = 120000000ULL;
    if (rt->cfg.stateless_window_min == 0u) rt->cfg.stateless_window_min = 30u;

    uint32_t seed_seq = 1u;
    (void)ash_csprng(&seed_seq, sizeof(seed_seq));
    ash_atomic_init(&rt->seq_counter, (uint64_t)(seed_seq & 0x3FFFFFu));
    ash_atomic_init(&rt->stat_fwd_pkts, 0ULL);
    ash_atomic_init(&rt->stat_fwd_bytes, 0ULL);
    ash_atomic_init(&rt->stat_drop_auth, 0ULL);
    ash_atomic_init(&rt->stat_drop_qos, 0ULL);
    ash_atomic_init(&rt->stat_hydrated, 0ULL);

    ash_mutex_init(&rt->global_tb_mu);
    /* Shard aggregate bandwidth caps when >= 8192 kbps for zero cross-shard lock contention;
     * use exact global bucket for small test limits (< 8192 kbps). */
    bool can_shard_free  = (cfg->free_pool_total_kbps == 0u) || (cfg->free_pool_total_kbps >= 8192u);
    bool can_shard_total = (cfg->total_bw_kbps == 0u) || (cfg->total_bw_kbps >= 8192u);
    rt->sharded_bw_limit = can_shard_free && can_shard_total;

    ash_tb_init(&rt->global_free_tb, cfg->free_pool_total_kbps, 100u);
    ash_tb_init(&rt->global_total_tb, cfg->total_bw_kbps, 100u);

    uint32_t per_shard = ((max_sessions * 3u) / 2u) / ASH_RELAY_SHARDS;
    if (per_shard < 16u) per_shard = 16u;
    uint32_t cap = pow2_ceil_u32(per_shard);

    for (uint32_t i = 0u; i < ASH_RELAY_SHARDS; ++i) {
        ash_mutex_init(&rt->shards[i].mu);
        rt->shards[i].cap  = cap;
        rt->shards[i].mask = cap - 1u;
        ash_tb_init(&rt->shards[i].shard_free_tb,
                    (cfg->free_pool_total_kbps > 0u) ? (cfg->free_pool_total_kbps / ASH_RELAY_SHARDS) : 0u,
                    100u);
        ash_tb_init(&rt->shards[i].shard_total_tb,
                    (cfg->total_bw_kbps > 0u) ? (cfg->total_bw_kbps / ASH_RELAY_SHARDS) : 0u,
                    100u);
        rt->shards[i].slots = (ash_relay_sess_t *)calloc(cap, sizeof(ash_relay_sess_t));
        if (rt->shards[i].slots == NULL) {
            for (uint32_t j = 0u; j <= i; ++j) {
                free(rt->shards[j].slots);
                rt->shards[j].slots = NULL;
                ash_mutex_destroy(&rt->shards[j].mu);
            }
            ash_mutex_destroy(&rt->global_tb_mu);
            return false;
        }
    }
    return true;
}

void ash_relay_destroy(ash_relay_table_t *rt) {
    if (rt == NULL) return;
    for (uint32_t i = 0u; i < ASH_RELAY_SHARDS; ++i) {
        if (rt->shards[i].slots != NULL) {
            free(rt->shards[i].slots);
            rt->shards[i].slots = NULL;
        }
        ash_mutex_destroy(&rt->shards[i].mu);
    }
    ash_mutex_destroy(&rt->global_tb_mu);
}

bool ash_relay_create_session(ash_relay_table_t *rt,
                              const char *host_name,
                              uint32_t req,
                              const ash_ep_t *host_ep,
                              uint64_t host_tcp_conn,
                              const ash_ep_t *client_ep,
                              uint64_t client_tcp_conn,
                              uint8_t tier,
                              uint16_t pool_id,
                              uint32_t max_kbps,
                              uint64_t now_us,
                              uint32_t now_wall_min,
                              uint32_t *out_sess,
                              uint32_t *out_tok_h,
                              uint32_t *out_tok_c) {
    /* 1. Check if client retransmitted the same LOOKUP (req + client_ep) */
    if (req != 0u) {
        for (uint32_t sidx = 0u; sidx < ASH_RELAY_SHARDS; ++sidx) {
            ash_relay_shard_t *sh = &rt->shards[sidx];
            ash_mutex_lock(&sh->mu);
            for (uint32_t i = 0u; i < sh->cap; ++i) {
                ash_relay_sess_t *s = &sh->slots[i];
                if (sess_alive(s, now_us, rt->cfg.sess_ttl_us) &&
                    (s->req == req) && ash_ep_eq(&s->c_init_obs, client_ep)) {
                    s->h_ep         = *host_ep;
                    s->h_tcp_conn   = host_tcp_conn;
                    s->c_ep         = *client_ep;
                    s->c_tcp_conn   = client_tcp_conn;
                    s->last_seen_us = now_us;
                    uint32_t rs = s->sess, th = s->tok_h, tc = s->tok_c;
                    ash_mutex_unlock(&sh->mu);
                    if (out_sess != NULL)  *out_sess  = rs;
                    if (out_tok_h != NULL) *out_tok_h = th;
                    if (out_tok_c != NULL) *out_tok_c = tc;
                    return true;
                }
            }
            ash_mutex_unlock(&sh->mu);
        }
    }

    /* 2. Mint new deterministic-token session ID */
    for (unsigned attempt = 0u; attempt < 8u; ++attempt) {
        uint32_t seq22 = (uint32_t)ash_atomic_inc(&rt->seq_counter) & 0x3FFFFFu;
        if (seq22 == 0u) seq22 = (uint32_t)ash_atomic_inc(&rt->seq_counter) & 0x3FFFFFu;
        uint32_t sess = ash_make_sess_id(tier, now_wall_min, seq22);
        uint32_t th = 0u, tc = 0u;
        ash_derive_sess_tokens(rt->cfg.cluster_secret, sess, &th, &tc);

        ash_relay_shard_t *sh = &rt->shards[sess & (ASH_RELAY_SHARDS - 1u)];
        ash_mutex_lock(&sh->mu);
        ash_relay_sess_t *existing = shard_find_sess(sh, sess, now_us, rt->cfg.sess_ttl_us, NULL);
        if (existing != NULL) {
            ash_mutex_unlock(&sh->mu);
            continue;
        }
        ash_relay_sess_t *s = shard_alloc_sess(sh, sess, now_us, rt->cfg.sess_ttl_us);
        if (s == NULL) {
            ash_mutex_unlock(&sh->mu);
            return false;
        }
        s->tok_h        = th;
        s->tok_c        = tc;
        s->req          = req;
        s->tier         = tier;
        s->pool_id      = pool_id;
        s->last_seen_us = now_us;
        s->h_ep         = *host_ep;
        s->h_tcp_conn   = host_tcp_conn;
        s->c_ep         = *client_ep;
        s->c_tcp_conn   = client_tcp_conn;
        s->c_init_obs   = *client_ep;
        ash_tb_init(&s->tb, max_kbps, 100u);
        if (host_name != NULL) {
            size_t nl = strlen(host_name);
            if (nl > ASH_MAX_NAME_LEN) nl = ASH_MAX_NAME_LEN;
            memcpy(s->host_name, host_name, nl);
            s->host_name[nl] = '\0';
        }
        ash_mutex_unlock(&sh->mu);

        if (out_sess != NULL)  *out_sess  = sess;
        if (out_tok_h != NULL) *out_tok_h = th;
        if (out_tok_c != NULL) *out_tok_c = tc;
        return true;
    }
    return false;
}

bool ash_relay_bind_ticket(ash_relay_table_t *rt,
                           const ash_msg_relay_bind_t *bind_msg,
                           const ash_ep_t *from_ep,
                           uint64_t tcp_conn_id,
                           uint64_t now_us,
                           uint32_t now_wall_sec,
                           ash_msg_relay_bind_ok_t *out_ok) {
    memset(out_ok, 0, sizeof(*out_ok));
    ash_ticket_claims_t claims;
    if (!ash_ticket_verify(rt->cfg.cluster_secret, bind_msg->ticket, now_wall_sec, &claims)) {
        out_ok->status = (uint8_t)ASH_STATUS_AUTH_FAILED;
        (void)ash_atomic_inc(&rt->stat_drop_auth);
        return false;
    }
    /* Dedicated Enterprise Pool enforcement */
    if ((rt->cfg.node_pool_id != 0u) && (claims.pool_id != rt->cfg.node_pool_id)) {
        out_ok->status = (uint8_t)ASH_STATUS_AUTH_FAILED;
        (void)ash_atomic_inc(&rt->stat_drop_auth);
        return false;
    }

    uint32_t th = 0u, tc = 0u;
    ash_derive_sess_tokens(rt->cfg.cluster_secret, claims.sess, &th, &tc);

    ash_relay_shard_t *sh = &rt->shards[claims.sess & (ASH_RELAY_SHARDS - 1u)];
    ash_mutex_lock(&sh->mu);
    ash_relay_sess_t *s = shard_find_sess(sh, claims.sess, now_us, rt->cfg.sess_ttl_us, NULL);
    if (s == NULL) {
        s = shard_alloc_sess(sh, claims.sess, now_us, rt->cfg.sess_ttl_us);
        if (s == NULL) {
            ash_mutex_unlock(&sh->mu);
            out_ok->status = (uint8_t)ASH_STATUS_CAPACITY_FULL;
            return false;
        }
        s->tok_h   = th;
        s->tok_c   = tc;
        s->tier    = claims.tier;
        s->pool_id = claims.pool_id;
        uint32_t kbps = (claims.max_kbps != 0u) ? claims.max_kbps
                                                : rt->cfg.tier_kbps[claims.tier & 3u];
        ash_tb_init(&s->tb, kbps, 100u);
        (void)ash_atomic_inc(&rt->stat_hydrated);
    } else if ((claims.max_kbps != 0u) && (s->tb.rate_kbps != claims.max_kbps)) {
        ash_tb_reconfig(&s->tb, claims.max_kbps, 100u);
    }

    s->last_seen_us = now_us;
    if (bind_msg->role == 1u) {
        s->h_ep       = *from_ep;
        s->h_tcp_conn = tcp_conn_id;
    } else {
        s->c_ep       = *from_ep;
        s->c_tcp_conn = tcp_conn_id;
    }
    uint32_t max_kbps = s->tb.rate_kbps;
    ash_mutex_unlock(&sh->mu);

    out_ok->status   = (uint8_t)ASH_STATUS_OK;
    out_ok->sess     = claims.sess;
    out_ok->tok      = (bind_msg->role == 1u) ? th : tc;
    out_ok->max_kbps = max_kbps;
    return true;
}

void ash_relay_on_host_rebind(ash_relay_table_t *rt,
                              const char *host_name,
                              const ash_ep_t *new_ep,
                              uint64_t new_tcp_conn,
                              uint64_t now_us) {
    if ((rt == NULL) || (host_name == NULL) || (host_name[0] == '\0')) return;
    for (uint32_t sidx = 0u; sidx < ASH_RELAY_SHARDS; ++sidx) {
        ash_relay_shard_t *sh = &rt->shards[sidx];
        ash_mutex_lock(&sh->mu);
        for (uint32_t i = 0u; i < sh->cap; ++i) {
            ash_relay_sess_t *s = &sh->slots[i];
            if (sess_alive(s, now_us, rt->cfg.sess_ttl_us) &&
                (strcmp(s->host_name, host_name) == 0)) {
                s->h_ep       = *new_ep;
                s->h_tcp_conn = new_tcp_conn;
            }
        }
        ash_mutex_unlock(&sh->mu);
    }
}

bool ash_relay_nat_peer(ash_relay_table_t *rt,
                        uint32_t sess,
                        uint32_t tok,
                        uint64_t now_us,
                        ash_ep_t *tester_main,
                        ash_ep_t *peer_ep,
                        uint64_t *peer_tcp_conn) {
    if ((sess == 0u) || (tok == 0u)) return false;
    ash_relay_shard_t *sh = &rt->shards[sess & (ASH_RELAY_SHARDS - 1u)];
    ash_mutex_lock(&sh->mu);
    const ash_relay_sess_t *s = shard_find_sess(sh, sess, now_us, rt->cfg.sess_ttl_us, NULL);
    bool ok = (s != NULL) && ((tok == s->tok_h) || (tok == s->tok_c));
    if (ok) {
        bool host      = (tok == s->tok_h);
        *tester_main   = host ? s->h_ep : s->c_ep;
        *peer_ep       = host ? s->c_ep : s->h_ep;
        *peer_tcp_conn = host ? s->c_tcp_conn : s->h_tcp_conn;
    }
    ash_mutex_unlock(&sh->mu);
    return ok;
}

static bool consume_pool_qos_locked(ash_relay_table_t *rt,
                                    ash_relay_shard_t *sh,
                                    uint8_t tier,
                                    size_t bytes,
                                    uint64_t now_us) {
    if (rt->sharded_bw_limit) {
        if ((tier == (uint8_t)ASH_TIER_FREE) && !ash_tb_consume(&sh->shard_free_tb, bytes, now_us)) {
            return false;
        }
        return ash_tb_consume(&sh->shard_total_tb, bytes, now_us);
    }
    ash_mutex_lock(&rt->global_tb_mu);
    bool ok = true;
    if ((tier == (uint8_t)ASH_TIER_FREE) && !ash_tb_consume(&rt->global_free_tb, bytes, now_us)) {
        ok = false;
    }
    if (ok && !ash_tb_consume(&rt->global_total_tb, bytes, now_us)) {
        ok = false;
    }
    ash_mutex_unlock(&rt->global_tb_mu);
    return ok;
}

ash_relay_route_t ash_relay_on_packet(ash_relay_table_t *rt,
                                      uint8_t *pkt,
                                      size_t pkt_len,
                                      const ash_ep_t *from_ep,
                                      uint64_t from_tcp_conn,
                                      uint64_t now_us,
                                      uint32_t now_wall_min) {
    ash_relay_route_t route;
    memset(&route, 0, sizeof(route));
    route.kind = ASH_ROUTE_DROP;

    uint32_t sess = 0u, tok = 0u;
    size_t pl_len = ash_relay_unwrap(pkt, pkt_len, &sess, &tok);
    if ((pl_len == 0u) || (sess == 0u) || (tok == 0u)) {
        route.bad_token = true;
        (void)ash_atomic_inc(&rt->stat_drop_auth);
        return route;
    }

    ash_relay_shard_t *sh = &rt->shards[sess & (ASH_RELAY_SHARDS - 1u)];
    ash_mutex_lock(&sh->mu);
    ash_relay_sess_t *free_cand = NULL;
    ash_relay_sess_t *s = shard_find_sess(sh, sess, now_us, rt->cfg.sess_ttl_us, &free_cand);

    /* Stateless auto-hydration: allows distributed Relay nodes & zero-RTT server restart recovery! */
    if (s == NULL) {
        ash_mutex_unlock(&sh->mu);

        /* Dedicated nodes require explicit Relay Ticket bind to enforce pool_id */
        if (rt->cfg.node_pool_id != 0u) {
            route.bad_token = true;
            (void)ash_atomic_inc(&rt->stat_drop_auth);
            return route;
        }
        bool is_host = false;
        uint8_t tier = 0u;
        if (!ash_verify_stateless_relay_tok(rt->cfg.cluster_secret, sess, tok,
                                            now_wall_min, rt->cfg.stateless_window_min,
                                            &is_host, &tier)) {
            route.bad_token = true;
            (void)ash_atomic_inc(&rt->stat_drop_auth);
            return route;
        }

        uint32_t th = 0u, tc = 0u;
        ash_derive_sess_tokens(rt->cfg.cluster_secret, sess, &th, &tc);

        ash_mutex_lock(&sh->mu);
        s = shard_find_sess(sh, sess, now_us, rt->cfg.sess_ttl_us, NULL);
        if (s == NULL) {
            s = shard_alloc_sess(sh, sess, now_us, rt->cfg.sess_ttl_us);
            if (s == NULL) {
                ash_mutex_unlock(&sh->mu);
                return route;
            }
            s->tok_h = th;
            s->tok_c = tc;
            s->tier  = tier;
            ash_tb_init(&s->tb, rt->cfg.tier_kbps[tier & 3u], 100u);
            (void)ash_atomic_inc(&rt->stat_hydrated);
        }
    }

    if ((tok != s->tok_h) && (tok != s->tok_c)) {
        ash_mutex_unlock(&sh->mu);
        route.bad_token = true;
        (void)ash_atomic_inc(&rt->stat_drop_auth);
        return route;
    }

    /* Enforce per-session + tiered pool QoS token buckets */
    if (!ash_tb_consume(&s->tb, pkt_len, now_us) ||
        !consume_pool_qos_locked(rt, sh, s->tier, pkt_len, now_us)) {
        ash_mutex_unlock(&sh->mu);
        (void)ash_atomic_inc(&rt->stat_drop_qos);
        return route;
    }

    bool from_host = (tok == s->tok_h);
    if (from_host) {
        s->h_ep       = *from_ep;
        s->h_tcp_conn = from_tcp_conn;
    } else {
        s->c_ep       = *from_ep;
        s->c_tcp_conn = from_tcp_conn;
    }
    s->last_seen_us = now_us;
    s->fwd_pkts    += 1ULL;
    s->fwd_bytes   += (uint64_t)pl_len;

    ash_ep_t dst_ep   = from_host ? s->c_ep : s->h_ep;
    uint64_t dst_tcp  = from_host ? s->c_tcp_conn : s->h_tcp_conn;
    ash_mutex_unlock(&sh->mu);

    /* Zero out sender's secret token before forwarding to peer (in-place, zero-copy) */
    pkt[5] = 0u;
    pkt[6] = 0u;
    pkt[7] = 0u;
    pkt[8] = 0u;

    if (dst_tcp != 0ULL) {
        route.kind         = ASH_ROUTE_TCP;
        route.dst_tcp_conn = dst_tcp;
        (void)ash_atomic_inc(&rt->stat_fwd_pkts);
        (void)ash_atomic_add(&rt->stat_fwd_bytes, (uint64_t)pkt_len);
    } else if (dst_ep.fam != 0u) {
        route.kind    = ASH_ROUTE_UDP;
        route.dst_udp = dst_ep;
        (void)ash_atomic_inc(&rt->stat_fwd_pkts);
        (void)ash_atomic_add(&rt->stat_fwd_bytes, (uint64_t)pkt_len);
    } else {
        route.kind = ASH_ROUTE_NONE;
    }
    return route;
}

void ash_relay_on_tcp_closed(ash_relay_table_t *rt, uint64_t tcp_conn_id) {
    if ((rt == NULL) || (tcp_conn_id == 0ULL)) return;
    for (uint32_t sidx = 0u; sidx < ASH_RELAY_SHARDS; ++sidx) {
        ash_relay_shard_t *sh = &rt->shards[sidx];
        ash_mutex_lock(&sh->mu);
        for (uint32_t i = 0u; i < sh->cap; ++i) {
            ash_relay_sess_t *s = &sh->slots[i];
            if (s->sess == 0u) continue;
            if (s->h_tcp_conn == tcp_conn_id) {
                s->h_tcp_conn = 0ULL;
                memset(&s->h_ep, 0, sizeof(s->h_ep));
            }
            if (s->c_tcp_conn == tcp_conn_id) {
                s->c_tcp_conn = 0ULL;
                memset(&s->c_ep, 0, sizeof(s->c_ep));
            }
        }
        ash_mutex_unlock(&sh->mu);
    }
}

void ash_relay_sweep_step(ash_relay_table_t *rt, uint64_t now_us) {
    for (uint32_t sidx = 0u; sidx < ASH_RELAY_SHARDS; ++sidx) {
        ash_relay_shard_t *sh = &rt->shards[sidx];
        ash_mutex_lock(&sh->mu);
        uint32_t batch = (sh->cap < 32u) ? sh->cap : 32u;
        for (uint32_t k = 0u; k < batch; ++k) {
            uint32_t idx = (sh->sweep_cursor + k) & sh->mask;
            ash_relay_sess_t *s = &sh->slots[idx];
            if ((s->sess != 0u) && !sess_alive(s, now_us, rt->cfg.sess_ttl_us)) {
                s->sess = 0u;
            }
        }
        sh->sweep_cursor = (sh->sweep_cursor + batch) & sh->mask;
        ash_mutex_unlock(&sh->mu);
    }
}

uint32_t ash_relay_active_sessions(ash_relay_table_t *rt, uint64_t now_us) {
    uint32_t count = 0u;
    for (uint32_t sidx = 0u; sidx < ASH_RELAY_SHARDS; ++sidx) {
        ash_relay_shard_t *sh = &rt->shards[sidx];
        ash_mutex_lock(&sh->mu);
        for (uint32_t i = 0u; i < sh->cap; ++i) {
            if (sess_alive(&sh->slots[i], now_us, rt->cfg.sess_ttl_us)) {
                count += 1u;
            }
        }
        ash_mutex_unlock(&sh->mu);
    }
    return count;
}

size_t ash_relay_memory_bytes(const ash_relay_table_t *rt) {
    if (rt == NULL) return 0u;
    size_t per_shard = (size_t)rt->shards[0].cap * sizeof(ash_relay_sess_t);
    return sizeof(*rt) + ((size_t)ASH_RELAY_SHARDS * per_shard);
}
