#include "ash_registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Persistent keystore binary record:
 *   magic[4] = "ASHK" | version = 1 | name_len u8 | reserved u16 | name[64] | pubkey[32] | sha256[8]
 *   Total = 112 bytes fixed per pinned device. */
#define KS_REC_BYTES 112u

static uint32_t next_pow2_u32(uint32_t v) {
    uint32_t p = 16u;
    while ((p < v) && (p < (1u << 24u))) {
        p <<= 1u;
    }
    return p;
}

static uint64_t hash_device_name(const uint8_t sip_key[16], const char *name) {
    uint64_t h = ash_siphash24(sip_key, name, strlen(name));
    return (h != 0ULL) ? h : 1ULL;
}

static bool host_is_alive(const ash_host_entry_t *e, uint64_t now_us, uint64_t ttl_us) {
    if ((e->hash == 0ULL) || (e->online == 0u)) return false;
    if (now_us < e->last_seen_us) return true;
    return (now_us - e->last_seen_us) < ttl_us;
}

static ash_host_entry_t *shard_find_or_insert(ash_reg_shard_t *sh,
                                              uint64_t h,
                                              const char *name,
                                              uint64_t now_us,
                                              uint64_t ttl_us,
                                              bool create_if_missing) {
    uint32_t idx        = (uint32_t)(h >> 6u) & sh->mask;
    ash_host_entry_t *first_free    = NULL;
    ash_host_entry_t *first_offline = NULL;
    ash_host_entry_t *first_unpin   = NULL;

    for (uint32_t probe = 0u; probe < sh->cap; ++probe) {
        ash_host_entry_t *e = &sh->slots[(idx + probe) & sh->mask];
        if (e->hash == 0ULL) {
            if (first_free == NULL) first_free = e;
            break; /* Linear probe chain ends at empty slot */
        }
        if ((e->hash == h) && (strcmp(e->name, name) == 0)) {
            return e;
        }
        if (!host_is_alive(e, now_us, ttl_us)) {
            if ((e->has_pubkey == 0u) && (first_unpin == NULL)) {
                first_unpin = e;
            }
            if (first_offline == NULL) {
                first_offline = e;
            }
        }
    }

    if (!create_if_missing) return NULL;
    ash_host_entry_t *victim = (first_free != NULL) ? first_free
                             : (first_unpin != NULL) ? first_unpin
                             : first_offline;
    if (victim == NULL) return NULL;

    memset(victim, 0, sizeof(*victim));
    victim->hash = h;
    size_t nl = strlen(name);
    if (nl > ASH_MAX_NAME_LEN) nl = ASH_MAX_NAME_LEN;
    memcpy(victim->name, name, nl);
    victim->name[nl] = '\0';
    return victim;
}

static void keystore_append(ash_registry_t *reg, const char *name, const uint8_t pubkey[32]) {
    if ((reg->cfg.keystore_path == NULL) || (reg->cfg.keystore_path[0] == '\0')) return;

    uint8_t rec[KS_REC_BYTES];
    memset(rec, 0, sizeof(rec));
    rec[0] = (uint8_t)'A';
    rec[1] = (uint8_t)'S';
    rec[2] = (uint8_t)'H';
    rec[3] = (uint8_t)'K';
    rec[4] = 1u;
    size_t nl = strlen(name);
    if (nl > ASH_MAX_NAME_LEN) nl = ASH_MAX_NAME_LEN;
    rec[5] = (uint8_t)nl;
    for (size_t i = 0u; i < nl; ++i) {
        rec[8u + i] = (uint8_t)name[i];
    }
    memcpy(rec + 72u, pubkey, 32u);

    uint8_t digest[ASH_SHA256_BYTES];
    ash_sha256(rec, 104u, digest);
    memcpy(rec + 104u, digest, 8u);

    ash_mutex_lock(&reg->ks_mu);
    FILE *f = fopen(reg->cfg.keystore_path, "ab");
    if (f != NULL) {
        (void)fwrite(rec, 1u, sizeof(rec), f);
        fflush(f);
        fclose(f);
    }
    ash_mutex_unlock(&reg->ks_mu);
}

static void keystore_load(ash_registry_t *reg) {
    if ((reg->cfg.keystore_path == NULL) || (reg->cfg.keystore_path[0] == '\0')) return;
    FILE *f = fopen(reg->cfg.keystore_path, "rb");
    if (f == NULL) return;

    uint8_t rec[KS_REC_BYTES];
    while (fread(rec, 1u, sizeof(rec), f) == sizeof(rec)) {
        if ((rec[0] != (uint8_t)'A') || (rec[1] != (uint8_t)'S') ||
            (rec[2] != (uint8_t)'H') || (rec[3] != (uint8_t)'K') || (rec[4] != 1u)) {
            continue;
        }
        uint8_t nl = rec[5];
        if ((nl == 0u) || (nl > ASH_MAX_NAME_LEN)) continue;
        uint8_t digest[ASH_SHA256_BYTES];
        ash_sha256(rec, 104u, digest);
        if (!ash_ct_equal(digest, rec + 104u, 8u)) continue;

        char name[ASH_MAX_NAME_LEN + 1u];
        memcpy(name, rec + 8u, nl);
        name[nl] = '\0';

        uint64_t h = hash_device_name(reg->sip_key, name);
        ash_reg_shard_t *sh = &reg->shards[(uint32_t)(h & (ASH_REG_SHARDS - 1u))];
        ash_mutex_lock(&sh->mu);
        ash_host_entry_t *e = shard_find_or_insert(sh, h, name, 0ULL, reg->cfg.host_ttl_us, true);
        if (e != NULL) {
            e->has_pubkey = 1u;
            memcpy(e->pubkey, rec + 72u, 32u);
        }
        ash_mutex_unlock(&sh->mu);
    }
    fclose(f);
}

bool ash_registry_init(ash_registry_t *reg, uint32_t max_hosts, const ash_registry_cfg_t *cfg) {
    if ((reg == NULL) || (cfg == NULL)) return false;
    memset(reg, 0, sizeof(*reg));
    reg->cfg = *cfg;
    if (reg->cfg.host_ttl_us == 0ULL) reg->cfg.host_ttl_us = 60000000ULL;
    if (reg->cfg.node_ttl_us == 0ULL) reg->cfg.node_ttl_us = 15000000ULL;
    if (!ash_csprng(reg->sip_key, sizeof(reg->sip_key))) return false;
    if (!ash_csprng(reg->nonce_key, sizeof(reg->nonce_key))) return false;

    ash_mutex_init(&reg->ks_mu);
    ash_mutex_init(&reg->nodes_mu);
    ash_atomic_init(&reg->stat_reg_ok, 0ULL);
    ash_atomic_init(&reg->stat_auth_fail, 0ULL);
    ash_atomic_init(&reg->stat_lookups, 0ULL);
    ash_atomic_init(&reg->stat_notfound, 0ULL);

    /* Ensure <= 65% load factor at max_hosts across 64 shards */
    uint32_t target_per_shard = ((max_hosts * 3u) / 2u) / ASH_REG_SHARDS;
    if (target_per_shard < 16u) target_per_shard = 16u;
    uint32_t cap = next_pow2_u32(target_per_shard);

    for (uint32_t i = 0u; i < ASH_REG_SHARDS; ++i) {
        ash_mutex_init(&reg->shards[i].mu);
        reg->shards[i].cap   = cap;
        reg->shards[i].mask  = cap - 1u;
        reg->shards[i].slots = (ash_host_entry_t *)calloc(cap, sizeof(ash_host_entry_t));
        if (reg->shards[i].slots == NULL) {
            for (uint32_t j = 0u; j <= i; ++j) {
                free(reg->shards[j].slots);
                reg->shards[j].slots = NULL;
                ash_mutex_destroy(&reg->shards[j].mu);
            }
            ash_mutex_destroy(&reg->nodes_mu);
            ash_mutex_destroy(&reg->ks_mu);
            return false;
        }
    }

    keystore_load(reg);
    return true;
}

void ash_registry_destroy(ash_registry_t *reg) {
    if (reg == NULL) return;
    for (uint32_t i = 0u; i < ASH_REG_SHARDS; ++i) {
        if (reg->shards[i].slots != NULL) {
            free(reg->shards[i].slots);
            reg->shards[i].slots = NULL;
        }
        ash_mutex_destroy(&reg->shards[i].mu);
    }
    ash_mutex_destroy(&reg->nodes_mu);
    ash_mutex_destroy(&reg->ks_mu);
}

ash_status_t ash_registry_on_reg_v1(ash_registry_t *reg,
                                    const ash_rdv1_msg_t *m,
                                    const ash_ep_t *from,
                                    uint64_t tcp_conn_id,
                                    uint64_t now_us,
                                    bool *out_addr_changed) {
    if (out_addr_changed != NULL) *out_addr_changed = false;
    if (!reg->cfg.allow_v1_unauth) {
        (void)ash_atomic_inc(&reg->stat_auth_fail);
        return ASH_STATUS_AUTH_FAILED;
    }

    uint64_t h = hash_device_name(reg->sip_key, m->name);
    ash_reg_shard_t *sh = &reg->shards[(uint32_t)(h & (ASH_REG_SHARDS - 1u))];

    ash_mutex_lock(&sh->mu);
    ash_host_entry_t *e = shard_find_or_insert(sh, h, m->name, now_us, reg->cfg.host_ttl_us, true);
    if (e == NULL) {
        ash_mutex_unlock(&sh->mu);
        return ASH_STATUS_CAPACITY_FULL;
    }
    /* Critical security invariant: once an ID is claimed by an Ed25519 v2 key, unauthenticated
     * v1 packets can NEVER overwrite or hijack that ID! */
    if (e->has_pubkey != 0u) {
        ash_mutex_unlock(&sh->mu);
        (void)ash_atomic_inc(&reg->stat_auth_fail);
        return ASH_STATUS_AUTH_FAILED;
    }

    bool changed = (e->online == 0u) || !ash_ep_eq(&e->obs, from);
    e->online       = 1u;
    e->obs          = *from;
    e->tcp_conn_id  = tcp_conn_id;
    e->host_flags   = m->host_flags;
    e->tier         = (uint8_t)ASH_TIER_FREE;
    e->pool_id      = 0u;
    e->license_kbps = 0u;
    e->ncand        = m->ncand;
    for (uint8_t i = 0u; i < m->ncand; ++i) {
        e->cand[i] = m->cand[i];
    }
    e->last_seen_us = now_us;
    ash_mutex_unlock(&sh->mu);

    if (out_addr_changed != NULL) *out_addr_changed = changed;
    (void)ash_atomic_inc(&reg->stat_reg_ok);
    return ASH_STATUS_OK;
}

/* ---------------- v1 number ownership ---------------- */
#define NUMBER_NONCE_SLICE_US 60000000ULL

static void number_nonce(const ash_registry_t *reg, const ash_ep_t *from, uint64_t slice,
                         uint8_t out[ASH_OWN_NONCE_LEN]) {
    uint8_t in[1u + 1u + 16u + 2u + 8u];
    uint8_t mac[ASH_SHA256_BYTES];
    in[0] = from->fam;
    in[1] = (from->proto == 6u) ? 6u : 17u;
    memset(in + 2u, 0, 16u);
    memcpy(in + 2u, from->ip, (from->fam == 4u) ? 4u : 16u);
    ash_put_be16(in + 18u, from->port);
    ash_put_be64(in + 20u, slice);
    ash_hmac_sha256(reg->nonce_key, sizeof(reg->nonce_key), in, sizeof(in), mac);
    memcpy(out, mac, ASH_OWN_NONCE_LEN);
}

/* Caller holds the shard lock */
static void number_set_online(ash_host_entry_t *e, const ash_rdv1_msg_t *m, const ash_ep_t *from,
                              uint64_t tcp_conn_id, uint64_t now_us) {
    e->online       = 1u;
    e->obs          = *from;
    e->tcp_conn_id  = tcp_conn_id;
    e->host_flags   = m->host_flags;
    e->tier         = (uint8_t)ASH_TIER_FREE;
    e->pool_id      = 0u;
    e->license_kbps = 0u;
    e->ncand        = m->ncand;
    for (uint8_t i = 0u; i < m->ncand; ++i) {
        e->cand[i] = m->cand[i];
    }
    e->last_seen_us = now_us;
}

ash_number_result_t ash_registry_on_reg_number(ash_registry_t *reg,
                                               const ash_rdv1_msg_t *m,
                                               const ash_ep_t *from,
                                               uint64_t tcp_conn_id,
                                               uint64_t now_us,
                                               bool may_pin_new,
                                               bool *out_addr_changed,
                                               bool *out_newly_pinned,
                                               uint8_t out_nonce[ASH_OWN_NONCE_LEN]) {
    if (out_addr_changed != NULL) *out_addr_changed = false;
    if (out_newly_pinned != NULL) *out_newly_pinned = false;
    uint64_t h = hash_device_name(reg->sip_key, m->name);
    ash_reg_shard_t *sh = &reg->shards[(uint32_t)(h & (ASH_REG_SHARDS - 1u))];

    /* 1. Keepalive: the number is online at exactly this address, so the sender already proved it */
    if (m->has_own == 0u) {
        bool refreshed = false;
        ash_mutex_lock(&sh->mu);
        ash_host_entry_t *e = shard_find_or_insert(sh, h, m->name, now_us, reg->cfg.host_ttl_us, false);
        if ((e != NULL) && (e->has_pubkey != 0u) && host_is_alive(e, now_us, reg->cfg.host_ttl_us) &&
            ash_ep_eq(&e->obs, from) && (e->tcp_conn_id == tcp_conn_id)) {
            number_set_online(e, m, from, tcp_conn_id, now_us);
            refreshed = true;
        }
        ash_mutex_unlock(&sh->mu);
        if (refreshed) {
            (void)ash_atomic_inc(&reg->stat_reg_ok);
            return ASH_NUMBER_REGISTERED;
        }
    }

    /* 2. The proof must answer a nonce issued to this address in the current or the previous slice */
    uint64_t slice = now_us / NUMBER_NONCE_SLICE_US;
    uint8_t  cur[ASH_OWN_NONCE_LEN];
    uint8_t  prev[ASH_OWN_NONCE_LEN];
    number_nonce(reg, from, slice, cur);
    number_nonce(reg, from, slice - 1ULL, prev);
    if ((m->has_own == 0u) ||
        (!ash_ct_equal(m->own_nonce, cur, sizeof(cur)) && !ash_ct_equal(m->own_nonce, prev, sizeof(prev)))) {
        memcpy(out_nonce, cur, sizeof(cur));
        return ASH_NUMBER_CHALLENGE;
    }

    /* 3. Verify the signature BEFORE touching shard locks */
    if (!ash_rdv1_own_verify(m)) {
        (void)ash_atomic_inc(&reg->stat_auth_fail);
        return ASH_NUMBER_BAD_PROOF;
    }

    /* 4. First key to register the number owns it; the same key may move it to a new address */
    bool newly_pinned = false;
    ash_mutex_lock(&sh->mu);
    ash_host_entry_t *e = shard_find_or_insert(sh, h, m->name, now_us, reg->cfg.host_ttl_us, may_pin_new);
    if (e == NULL) {
        ash_mutex_unlock(&sh->mu);
        return may_pin_new ? ASH_NUMBER_FULL : ASH_NUMBER_LIMITED;
    }
    if ((e->has_pubkey == 0u) && !may_pin_new) {
        ash_mutex_unlock(&sh->mu);
        return ASH_NUMBER_LIMITED;
    }
    if (e->has_pubkey == 0u) {
        e->has_pubkey = 1u;
        memcpy(e->pubkey, m->own_pub, ASH_ED25519_PUB_LEN);
        newly_pinned = true;
    } else if (!ash_ct_equal(e->pubkey, m->own_pub, ASH_ED25519_PUB_LEN)) {
        ash_mutex_unlock(&sh->mu);
        (void)ash_atomic_inc(&reg->stat_auth_fail);
        return ASH_NUMBER_TAKEN;
    }
    bool changed = (e->online == 0u) || !ash_ep_eq(&e->obs, from);
    number_set_online(e, m, from, tcp_conn_id, now_us);
    ash_mutex_unlock(&sh->mu);

    if (newly_pinned) {
        keystore_append(reg, m->name, m->own_pub);
    }
    if (out_addr_changed != NULL) *out_addr_changed = changed;
    if (out_newly_pinned != NULL) *out_newly_pinned = newly_pinned;
    (void)ash_atomic_inc(&reg->stat_reg_ok);
    return ASH_NUMBER_REGISTERED;
}

ash_status_t ash_registry_on_reg_v2(ash_registry_t *reg,
                                    const ash_msg_reg_v2_t *m,
                                    const ash_ep_t *from,
                                    uint64_t tcp_conn_id,
                                    uint64_t now_us,
                                    uint64_t now_wall_ms,
                                    uint8_t *out_tier) {
    if (out_tier != NULL) *out_tier = (uint8_t)ASH_TIER_FREE;

    /* 1. Verify Ed25519 signature BEFORE touching shard locks */
    if (!ash_reg_v2_verify_sig(m)) {
        (void)ash_atomic_inc(&reg->stat_auth_fail);
        return ASH_STATUS_AUTH_FAILED;
    }

    /* 2. Verify optional commercial license token */
    ash_license_claims_t lic;
    memset(&lic, 0, sizeof(lic));
    lic.tier = (uint8_t)ASH_TIER_FREE;
    if (m->has_license) {
        if (!ash_license_verify(reg->cfg.license_secret, m->license, m->name, now_wall_ms, &lic)) {
            return ASH_STATUS_BAD_LICENSE;
        }
    }

    uint64_t h = hash_device_name(reg->sip_key, m->name);
    ash_reg_shard_t *sh = &reg->shards[(uint32_t)(h & (ASH_REG_SHARDS - 1u))];
    bool newly_pinned = false;

    ash_mutex_lock(&sh->mu);
    ash_host_entry_t *e = shard_find_or_insert(sh, h, m->name, now_us, reg->cfg.host_ttl_us, true);
    if (e == NULL) {
        ash_mutex_unlock(&sh->mu);
        return ASH_STATUS_CAPACITY_FULL;
    }

    if (e->has_pubkey != 0u) {
        if (!ash_ct_equal(e->pubkey, m->pubkey, ASH_ED25519_PUB_LEN)) {
            ash_mutex_unlock(&sh->mu);
            (void)ash_atomic_inc(&reg->stat_auth_fail);
            return ASH_STATUS_AUTH_FAILED;
        }
        if (m->ts_ms < e->last_auth_ts_ms) {
            ash_mutex_unlock(&sh->mu);
            return ASH_STATUS_REPLAY_REJECTED;
        }
    } else {
        e->has_pubkey = 1u;
        memcpy(e->pubkey, m->pubkey, ASH_ED25519_PUB_LEN);
        newly_pinned = true;
    }

    e->last_auth_ts_ms = m->ts_ms;
    e->online          = 1u;
    e->obs             = *from;
    e->tcp_conn_id     = tcp_conn_id;
    e->host_flags      = m->host_flags;
    if (m->nat_type != (uint8_t)ASH_NAT_UNKNOWN) {
        e->nat_type = m->nat_type;
    } else if (tcp_conn_id != 0ULL) {
        e->nat_type = (uint8_t)ASH_NAT_UDP_BLOCKED;
    }
    e->tier         = lic.tier;
    e->pool_id      = lic.pool_id;
    e->license_kbps = lic.max_kbps;
    e->ncand        = m->ncand;
    for (uint8_t i = 0u; i < m->ncand; ++i) {
        e->cand[i] = m->cand[i];
    }
    /* Append public TCP passive candidate if host reported tcp_port > 0 */
    if ((m->tcp_port > 0u) && (e->ncand < ASH_MAX_CANDS)) {
        ash_ep_t tcp_ep = *from;
        tcp_ep.proto = 6u;
        tcp_ep.port  = m->tcp_port;
        e->cand[e->ncand++] = tcp_ep;
    }
    e->last_seen_us = now_us;
    ash_mutex_unlock(&sh->mu);

    if (newly_pinned) {
        keystore_append(reg, m->name, m->pubkey);
    }
    if (out_tier != NULL) *out_tier = lic.tier;
    (void)ash_atomic_inc(&reg->stat_reg_ok);
    return ASH_STATUS_OK;
}

bool ash_registry_on_unreg_v2(ash_registry_t *reg,
                              const ash_msg_unreg_v2_t *m,
                              uint64_t now_wall_ms) {
    (void)now_wall_ms;
    if (!ash_unreg_v2_verify_sig(m)) return false;

    uint64_t h = hash_device_name(reg->sip_key, m->name);
    ash_reg_shard_t *sh = &reg->shards[(uint32_t)(h & (ASH_REG_SHARDS - 1u))];

    bool ok = false;
    ash_mutex_lock(&sh->mu);
    ash_host_entry_t *e = shard_find_or_insert(sh, h, m->name, 0ULL, reg->cfg.host_ttl_us, false);
    if ((e != NULL) && (e->has_pubkey != 0u) &&
        ash_ct_equal(e->pubkey, m->pubkey, ASH_ED25519_PUB_LEN) &&
        (m->ts_ms >= e->last_auth_ts_ms)) {
        e->last_auth_ts_ms = m->ts_ms;
        e->online          = 0u;
        e->tcp_conn_id     = 0ULL;
        ok = true;
    }
    ash_mutex_unlock(&sh->mu);
    return ok;
}

void ash_registry_on_nat_probe(ash_registry_t *reg, const ash_ep_t *from_secondary, uint64_t now_us) {
    /* Scan active hosts with matching source IP to infer Cone vs Symmetric NAT port stride */
    for (uint32_t s = 0u; s < ASH_REG_SHARDS; ++s) {
        ash_reg_shard_t *sh = &reg->shards[s];
        ash_mutex_lock(&sh->mu);
        for (uint32_t i = 0u; i < sh->cap; ++i) {
            ash_host_entry_t *e = &sh->slots[i];
            if (!host_is_alive(e, now_us, reg->cfg.host_ttl_us)) continue;
            if (!ash_ep_same_ip(&e->obs, from_secondary)) continue;
            e->probe2_port = from_secondary->port;
            int32_t diff = (int32_t)from_secondary->port - (int32_t)e->obs.port;
            if (diff == 0) {
                e->nat_type    = (uint8_t)ASH_NAT_OPEN_CONE;
                e->port_stride = 0;
            } else {
                e->nat_type = (uint8_t)ASH_NAT_SYMMETRIC;
                if ((diff >= -32767) && (diff <= 32767)) {
                    e->port_stride = (int16_t)diff;
                }
            }
        }
        ash_mutex_unlock(&sh->mu);
    }
}

bool ash_registry_lookup_host(ash_registry_t *reg,
                              const char *name,
                              uint64_t now_us,
                              ash_host_entry_t *out_snapshot) {
    (void)ash_atomic_inc(&reg->stat_lookups);
    uint64_t h = hash_device_name(reg->sip_key, name);
    ash_reg_shard_t *sh = &reg->shards[(uint32_t)(h & (ASH_REG_SHARDS - 1u))];

    bool found = false;
    ash_mutex_lock(&sh->mu);
    ash_host_entry_t *e = shard_find_or_insert(sh, h, name, now_us, reg->cfg.host_ttl_us, false);
    if ((e != NULL) && host_is_alive(e, now_us, reg->cfg.host_ttl_us)) {
        if (out_snapshot != NULL) *out_snapshot = *e;
        found = true;
    }
    ash_mutex_unlock(&sh->mu);

    if (!found) {
        (void)ash_atomic_inc(&reg->stat_notfound);
    }
    return found;
}

void ash_registry_on_tcp_closed(ash_registry_t *reg, uint64_t tcp_conn_id) {
    if ((reg == NULL) || (tcp_conn_id == 0ULL)) return;
    for (uint32_t s = 0u; s < ASH_REG_SHARDS; ++s) {
        ash_reg_shard_t *sh = &reg->shards[s];
        ash_mutex_lock(&sh->mu);
        for (uint32_t i = 0u; i < sh->cap; ++i) {
            if (sh->slots[i].tcp_conn_id == tcp_conn_id) {
                sh->slots[i].online      = 0u;
                sh->slots[i].tcp_conn_id = 0ULL;
            }
        }
        ash_mutex_unlock(&sh->mu);
    }
}

void ash_registry_sweep_step(ash_registry_t *reg, uint64_t now_us) {
    for (uint32_t s = 0u; s < ASH_REG_SHARDS; ++s) {
        ash_reg_shard_t *sh = &reg->shards[s];
        ash_mutex_lock(&sh->mu);
        uint32_t batch = (sh->cap < 32u) ? sh->cap : 32u;
        for (uint32_t k = 0u; k < batch; ++k) {
            uint32_t idx = (sh->sweep_cursor + k) & sh->mask;
            ash_host_entry_t *e = &sh->slots[idx];
            if ((e->online != 0u) && !host_is_alive(e, now_us, reg->cfg.host_ttl_us)) {
                e->online      = 0u;
                e->tcp_conn_id = 0ULL;
            }
        }
        sh->sweep_cursor = (sh->sweep_cursor + batch) & sh->mask;
        ash_mutex_unlock(&sh->mu);
    }
}

void ash_registry_upsert_node(ash_registry_t *reg, const ash_msg_node_hb_t *hb, uint64_t now_us) {
    ash_mutex_lock(&reg->nodes_mu);
    ash_relay_node_t *slot = NULL;
    for (size_t i = 0u; i < ASH_MAX_RELAY_NODES; ++i) {
        if (reg->nodes[i].used && (reg->nodes[i].node_id == hb->node_id)) {
            slot = &reg->nodes[i];
            break;
        }
    }
    if (slot == NULL) {
        for (size_t i = 0u; i < ASH_MAX_RELAY_NODES; ++i) {
            if (!reg->nodes[i].used ||
                ((now_us > reg->nodes[i].last_seen_us) &&
                 ((now_us - reg->nodes[i].last_seen_us) >= reg->cfg.node_ttl_us))) {
                slot = &reg->nodes[i];
                break;
            }
        }
    }
    if (slot != NULL) {
        slot->used            = true;
        slot->node_id         = hb->node_id;
        slot->tier_max        = hb->tier_max;
        slot->pool_id         = hb->pool_id;
        slot->region_id       = hb->region_id;
        slot->active_sessions = hb->active_sessions;
        slot->used_kbps       = hb->used_kbps;
        slot->cap_kbps        = hb->cap_kbps;
        slot->last_seen_us    = now_us;
        slot->public_udp      = hb->public_udp;
        slot->public_tcp      = hb->public_tcp;
    }
    ash_mutex_unlock(&reg->nodes_mu);
}

bool ash_registry_select_relay(ash_registry_t *reg,
                               uint8_t tier,
                               uint16_t pool_id,
                               bool need_tcp,
                               uint64_t now_us,
                               ash_ep_t *out_udp,
                               ash_ep_t *out_tcp) {
    ash_mutex_lock(&reg->nodes_mu);
    const ash_relay_node_t *best = NULL;
    uint64_t best_score = UINT64_MAX;

    for (size_t i = 0u; i < ASH_MAX_RELAY_NODES; ++i) {
        const ash_relay_node_t *n = &reg->nodes[i];
        if (!n->used) continue;
        if ((now_us > n->last_seen_us) && ((now_us - n->last_seen_us) >= reg->cfg.node_ttl_us)) {
            continue;
        }
        if (pool_id != 0u) {
            if (n->pool_id != pool_id) continue;
        } else {
            if (n->pool_id != 0u) continue;
            if (n->tier_max < tier) continue;
        }
        if (need_tcp && (n->public_tcp.fam == 0u)) continue;

        /* Score by utilization permille + active session count */
        uint64_t util = (n->cap_kbps > 0u) ? (((uint64_t)n->used_kbps * 1000ULL) / n->cap_kbps) : 0ULL;
        uint64_t score = (util * 10ULL) + (uint64_t)n->active_sessions;
        if (score < best_score) {
            best_score = score;
            best       = n;
        }
    }

    bool ok = false;
    if (best != NULL) {
        if (out_udp != NULL) *out_udp = best->public_udp;
        if (out_tcp != NULL) *out_tcp = best->public_tcp;
        ok = true;
    }
    ash_mutex_unlock(&reg->nodes_mu);
    return ok;
}

static bool has_private_cand(const ash_ep_t *cands, uint8_t n) {
    for (uint8_t i = 0u; i < n; ++i) {
        if (ash_ep_is_private(&cands[i])) return true;
    }
    return false;
}

static bool has_tcp_cand(const ash_ep_t *cands, uint8_t n) {
    for (uint8_t i = 0u; i < n; ++i) {
        if (cands[i].proto == 6u) return true;
    }
    return false;
}

ash_punch_strategy_t ash_decide_punch_strategy(const ash_host_entry_t *host,
                                               const ash_ep_t *client_obs,
                                               const ash_ep_t *client_cands,
                                               uint8_t client_ncand,
                                               uint8_t client_nat,
                                               bool prefer_tcp) {
    if (prefer_tcp ||
        (host->tcp_conn_id != 0ULL) ||
        (host->nat_type == (uint8_t)ASH_NAT_UDP_BLOCKED) ||
        (client_nat == (uint8_t)ASH_NAT_UDP_BLOCKED)) {
        if (has_tcp_cand(host->cand, host->ncand) || ((host->host_flags & ASH_HF_TCP_PUNCH) != 0u)) {
            return ASH_PUNCH_TCP_SIMUL;
        }
        return ASH_PUNCH_RELAY_ONLY;
    }

    /* Same public egress IP + private LAN candidates => LAN Direct without Hairpin NAT */
    if (ash_ep_same_ip(&host->obs, client_obs) &&
        (has_private_cand(host->cand, host->ncand) || has_private_cand(client_cands, client_ncand))) {
        return ASH_PUNCH_LAN_DIRECT;
    }

    /* Dual Symmetric NAT: UDP hole punch fails unless sequential stride prediction succeeds */
    if ((host->nat_type == (uint8_t)ASH_NAT_SYMMETRIC) &&
        (client_nat == (uint8_t)ASH_NAT_SYMMETRIC)) {
        int16_t st = host->port_stride;
        if ((st != 0) && (st >= -8) && (st <= 8)) {
            return ASH_PUNCH_UDP_SYM_PREDICT;
        }
        if (has_tcp_cand(host->cand, host->ncand)) {
            return ASH_PUNCH_TCP_SIMUL;
        }
        return ASH_PUNCH_RELAY_ONLY;
    }

    return ASH_PUNCH_UDP_CONE;
}

uint32_t ash_registry_effective_kbps(const ash_registry_t *reg,
                                     const ash_host_entry_t *host,
                                     const ash_license_claims_t *client_lic_or_null,
                                     uint8_t *out_tier,
                                     uint16_t *out_pool_id) {
    uint8_t  tier    = host->tier;
    uint16_t pool_id = host->pool_id;
    uint32_t explicit_kbps = host->license_kbps;

    if (client_lic_or_null != NULL) {
        if (client_lic_or_null->tier >= tier) {
            tier = client_lic_or_null->tier;
            if (client_lic_or_null->pool_id != 0u) {
                pool_id = client_lic_or_null->pool_id;
            }
            if (client_lic_or_null->max_kbps > explicit_kbps) {
                explicit_kbps = client_lic_or_null->max_kbps;
            }
        }
    }
    if (tier > (uint8_t)ASH_TIER_DEDICATED) tier = (uint8_t)ASH_TIER_FREE;
    if (out_tier != NULL)    *out_tier    = tier;
    if (out_pool_id != NULL) *out_pool_id = pool_id;

    if (explicit_kbps != 0u) return explicit_kbps;
    return reg->cfg.tier_kbps[tier];
}

uint32_t ash_registry_online_hosts(ash_registry_t *reg, uint64_t now_us) {
    uint32_t count = 0u;
    for (uint32_t s = 0u; s < ASH_REG_SHARDS; ++s) {
        ash_reg_shard_t *sh = &reg->shards[s];
        ash_mutex_lock(&sh->mu);
        for (uint32_t i = 0u; i < sh->cap; ++i) {
            if (host_is_alive(&sh->slots[i], now_us, reg->cfg.host_ttl_us)) {
                count += 1u;
            }
        }
        ash_mutex_unlock(&sh->mu);
    }
    return count;
}

uint32_t ash_registry_healthy_nodes(ash_registry_t *reg, uint64_t now_us) {
    uint32_t count = 0u;
    ash_mutex_lock(&reg->nodes_mu);
    for (size_t i = 0u; i < ASH_MAX_RELAY_NODES; ++i) {
        if (reg->nodes[i].used &&
            ((now_us <= reg->nodes[i].last_seen_us) ||
             ((now_us - reg->nodes[i].last_seen_us) < reg->cfg.node_ttl_us))) {
            count += 1u;
        }
    }
    ash_mutex_unlock(&reg->nodes_mu);
    return count;
}

size_t ash_registry_memory_bytes(const ash_registry_t *reg) {
    if (reg == NULL) return 0u;
    size_t per_shard = (size_t)reg->shards[0].cap * sizeof(ash_host_entry_t);
    return sizeof(*reg) + ((size_t)ASH_REG_SHARDS * per_shard);
}
