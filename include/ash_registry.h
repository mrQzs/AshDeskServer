#ifndef ASH_REGISTRY_H
#define ASH_REGISTRY_H

#include "ash_common.h"
#include "ash_wire.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ASH_REG_SHARDS      64u
#define ASH_MAX_RELAY_NODES 64u

typedef struct {
    uint64_t hash;             /* 0 = empty slot */
    uint64_t last_seen_us;     /* Monotonic timestamp of last heartbeat */
    uint64_t last_auth_ts_ms;  /* Anti-replay wall ms of last signed v2 msg */
    uint64_t tcp_conn_id;      /* Non-zero if host registered via TCP 443 */
    ash_ep_t obs;              /* Primary server-observed endpoint */
    uint16_t probe2_port;      /* Observed port on secondary NAT probe socket */
    int16_t  port_stride;      /* Detected NAT port allocation delta */
    uint8_t  online;
    uint8_t  has_pubkey;       /* 1 = Ed25519 key pinned (anti-hijack) */
    uint8_t  nat_type;
    uint8_t  host_flags;
    uint8_t  tier;
    uint8_t  ncand;
    uint16_t pool_id;
    uint32_t license_kbps;
    uint8_t  pubkey[ASH_ED25519_PUB_LEN];
    ash_ep_t cand[ASH_MAX_CANDS];
    char     name[ASH_MAX_NAME_LEN + 1u];
} ash_host_entry_t;

typedef struct {
    ash_mutex_t       mu;
    ash_host_entry_t *slots;
    uint32_t          cap;
    uint32_t          mask;
    uint32_t          sweep_cursor;
    uint8_t           cache_pad[ASH_CACHELINE_PAD];
} ash_reg_shard_t;

typedef struct {
    bool     used;
    uint32_t node_id;
    uint8_t  tier_max;
    uint16_t pool_id;
    uint16_t region_id;
    uint32_t active_sessions;
    uint32_t used_kbps;
    uint32_t cap_kbps;
    uint64_t last_seen_us;
    ash_ep_t public_udp;
    ash_ep_t public_tcp;
} ash_relay_node_t;

typedef struct {
    bool     allow_v1_unauth;
    uint64_t host_ttl_us;
    uint64_t node_ttl_us;
    uint32_t tier_kbps[4];       /* Default max_kbps per tier [FREE, PRO, VIP, DEDICATED] */
    uint8_t  license_secret[32];
    const char *keystore_path;   /* Optional binary keystore file for Ed25519 pin persistence */
} ash_registry_cfg_t;

typedef struct {
    ash_registry_cfg_t cfg;
    uint8_t            sip_key[16];
    uint8_t            nonce_key[32];   /* Per-process secret behind the number-ownership nonces (REG_CHAL) */
    ash_mutex_t        ks_mu;
    ash_reg_shard_t    shards[ASH_REG_SHARDS];

    ash_mutex_t        nodes_mu;
    ash_relay_node_t   nodes[ASH_MAX_RELAY_NODES];

    ash_atomic_u64     stat_reg_ok;
    ash_atomic_u64     stat_auth_fail;
    ash_atomic_u64     stat_lookups;
    ash_atomic_u64     stat_notfound;
} ash_registry_t;

bool ash_registry_init(ash_registry_t *reg, uint32_t max_hosts, const ash_registry_cfg_t *cfg);
void ash_registry_destroy(ash_registry_t *reg);

/* v1 registration (compatible with existing AshDesk adp_rdv) */
ash_status_t ash_registry_on_reg_v1(ash_registry_t *reg,
                                    const ash_rdv1_msg_t *m,
                                    const ash_ep_t *from,
                                    uint64_t tcp_conn_id,
                                    uint64_t now_us,
                                    bool *out_addr_changed);

/* v1 registration of an AshDesk number (a 9-digit name; AshDesk docs/号码连接设计.md §4.2). A number belongs to the first
 * Ed25519 key that registers it; the pin is the same one v2 uses and goes to the same keystore. */
typedef enum {
    ASH_NUMBER_REGISTERED = 0,  /* Online: answer REG_OK */
    ASH_NUMBER_CHALLENGE  = 1,  /* No proof, or its nonce was not issued to this address in the last two 60 s slices:
                                   answer REG_CHAL with out_nonce */
    ASH_NUMBER_TAKEN      = 2,  /* Pinned to another key: answer REG_TAKEN, the pinned host is untouched */
    ASH_NUMBER_BAD_PROOF  = 3,  /* Nonce is ours but the signature does not verify: a strike */
    ASH_NUMBER_FULL       = 4,  /* No slot left: no answer */
    ASH_NUMBER_LIMITED    = 5   /* A number nobody owns yet, and the caller did not allow a new pin: no answer */
} ash_number_result_t;

/* A REG without proof from the unchanged address of an online number is a keepalive and needs none. The nonce is
 * HMAC-SHA256(nonce_key, source endpoint | 60 s slice)[0..7]: stateless, useless from another address, and a
 * spoofed source never sees it, so signature checks are only spent on return-routable senders.
 * may_pin_new: whether this sender may still claim a number nobody owns (its daily allowance); numbers it already
 * owns register regardless. *out_newly_pinned tells the caller to count one against that allowance. */
ash_number_result_t ash_registry_on_reg_number(ash_registry_t *reg,
                                               const ash_rdv1_msg_t *m,
                                               const ash_ep_t *from,
                                               uint64_t tcp_conn_id,
                                               uint64_t now_us,
                                               bool may_pin_new,
                                               bool *out_addr_changed,
                                               bool *out_newly_pinned,
                                               uint8_t out_nonce[ASH_OWN_NONCE_LEN]);

/* v2 Ed25519 authenticated registration + commercial license evaluation */
ash_status_t ash_registry_on_reg_v2(ash_registry_t *reg,
                                    const ash_msg_reg_v2_t *m,
                                    const ash_ep_t *from,
                                    uint64_t tcp_conn_id,
                                    uint64_t now_us,
                                    uint64_t now_wall_ms,
                                    uint8_t *out_tier);

bool ash_registry_on_unreg_v2(ash_registry_t *reg,
                              const ash_msg_unreg_v2_t *m,
                              uint64_t now_wall_ms);

/* Update NAT mapping classification when secondary port receives probe from a registered IP */
void ash_registry_on_nat_probe(ash_registry_t *reg, const ash_ep_t *from_secondary, uint64_t now_us);

/* Thread-safe snapshot lookup of an online host */
bool ash_registry_lookup_host(ash_registry_t *reg,
                              const char *name,
                              uint64_t now_us,
                              ash_host_entry_t *out_snapshot);

/* Mark TCP-connected host offline immediately when its TCP socket closes */
void ash_registry_on_tcp_closed(ash_registry_t *reg, uint64_t tcp_conn_id);

/* Incremental O(1) slice eviction of expired hosts & nodes */
void ash_registry_sweep_step(ash_registry_t *reg, uint64_t now_us);

/* Distributed Relay Node Pool management */
void ash_registry_upsert_node(ash_registry_t *reg, const ash_msg_node_hb_t *hb, uint64_t now_us);
bool ash_registry_select_relay(ash_registry_t *reg,
                               uint8_t tier,
                               uint16_t pool_id,
                               bool need_tcp,
                               uint64_t now_us,
                               ash_ep_t *out_udp,
                               ash_ep_t *out_tcp);

/* NAT traversal & commercial tier policy helpers */
ash_punch_strategy_t ash_decide_punch_strategy(const ash_host_entry_t *host,
                                               const ash_ep_t *client_obs,
                                               const ash_ep_t *client_cands,
                                               uint8_t client_ncand,
                                               uint8_t client_nat,
                                               bool prefer_tcp);

uint32_t ash_registry_effective_kbps(const ash_registry_t *reg,
                                     const ash_host_entry_t *host,
                                     const ash_license_claims_t *client_lic_or_null,
                                     uint8_t *out_tier,
                                     uint16_t *out_pool_id);

uint32_t ash_registry_online_hosts(ash_registry_t *reg, uint64_t now_us);
uint32_t ash_registry_healthy_nodes(ash_registry_t *reg, uint64_t now_us);
size_t   ash_registry_memory_bytes(const ash_registry_t *reg);

#ifdef __cplusplus
}
#endif

#endif /* ASH_REGISTRY_H */
