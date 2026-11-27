#ifndef ASH_RELAY_H
#define ASH_RELAY_H

#include "ash_common.h"
#include "ash_ratelimit.h"
#include "ash_wire.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ASH_RELAY_SHARDS 64u

typedef enum {
    ASH_ROUTE_DROP = 0,
    ASH_ROUTE_NONE = 1, /* Authenticated & endpoint learned, peer endpoint not yet known */
    ASH_ROUTE_UDP  = 2,
    ASH_ROUTE_TCP  = 3
} ash_route_kind_t;

typedef struct {
    ash_route_kind_t kind;
    bool             bad_token; /* True if dropped due to invalid/unknown token (for IP strike) */
    ash_ep_t         dst_udp;
    uint64_t         dst_tcp_conn;
} ash_relay_route_t;

typedef struct {
    uint32_t sess;          /* 0 = empty slot */
    uint32_t tok_h;
    uint32_t tok_c;
    uint32_t req;
    uint16_t pool_id;
    uint8_t  tier;
    uint8_t  flags;
    uint64_t last_seen_us;
    uint64_t h_tcp_conn;    /* Non-zero if Host leg is over TCP 443 */
    uint64_t c_tcp_conn;    /* Non-zero if Client leg is over TCP 443 */
    ash_ep_t h_ep;
    ash_ep_t c_ep;
    ash_ep_t c_init_obs;
    ash_tb_t tb;
    uint64_t fwd_pkts;
    uint64_t fwd_bytes;
    char     host_name[ASH_MAX_NAME_LEN + 1u];
} ash_relay_sess_t;

typedef struct {
    ash_mutex_t       mu;
    ash_relay_sess_t *slots;
    uint32_t          cap;
    uint32_t          mask;
    uint32_t          sweep_cursor;
    ash_tb_t          shard_free_tb;
    ash_tb_t          shard_total_tb;
    uint8_t           cache_pad[ASH_CACHELINE_PAD];
} ash_relay_shard_t;

typedef struct {
    uint64_t sess_ttl_us;
    uint32_t stateless_window_min; /* Max age in minutes for auto-hydrating stateless tokens */
    uint16_t node_pool_id;         /* 0 = shared node, >0 = dedicated enterprise node */
    uint32_t tier_kbps[4];         /* Default per-session kbps for [FREE, PRO, VIP, DEDICATED] */
    uint32_t free_pool_total_kbps; /* Aggregate cap for all FREE sessions (0 = unthrottled) */
    uint32_t total_bw_kbps;        /* Aggregate cap for entire Relay server (0 = unthrottled) */
    uint8_t  cluster_secret[32];
} ash_relay_cfg_t;

typedef struct {
    ash_relay_cfg_t   cfg;
    bool              sharded_bw_limit;
    ash_mutex_t       global_tb_mu;
    ash_tb_t          global_free_tb;
    ash_tb_t          global_total_tb;
    ash_relay_shard_t shards[ASH_RELAY_SHARDS];

    ash_atomic_u64    seq_counter;
    ash_atomic_u64    stat_fwd_pkts;
    ash_atomic_u64    stat_fwd_bytes;
    ash_atomic_u64    stat_drop_auth;
    ash_atomic_u64    stat_drop_qos;
    ash_atomic_u64    stat_hydrated;
} ash_relay_table_t;

bool ash_relay_init(ash_relay_table_t *rt, uint32_t max_sessions, const ash_relay_cfg_t *cfg);
void ash_relay_destroy(ash_relay_table_t *rt);

/* Allocate or deduplicate a session during ID/Rendezvous lookup (All-in-One or Stateful mode) */
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
                              uint32_t *out_tok_c);

/* Bind a UDP or TCP 443 endpoint to a Relay session using a signed Cluster Relay Ticket */
bool ash_relay_bind_ticket(ash_relay_table_t *rt,
                           const ash_msg_relay_bind_t *bind_msg,
                           const ash_ep_t *from_ep,
                           uint64_t tcp_conn_id,
                           uint64_t now_us,
                           uint32_t now_wall_sec,
                           ash_msg_relay_bind_ok_t *out_ok);

/* Update host's UDP/TCP address across active sessions when host re-registers from a new NAT IP */
void ash_relay_on_host_rebind(ash_relay_table_t *rt,
                              const char *host_name,
                              const ash_ep_t *new_ep,
                              uint64_t new_tcp_conn,
                              uint64_t now_us);

/* v1 NAT_PEER: for a live session whose tok_h or tok_c is `tok`, the tester's main-port endpoint and the other side's
 * endpoint / TCP connection. False for an unknown session or a token of neither side. */
bool ash_relay_nat_peer(ash_relay_table_t *rt,
                        uint32_t sess,
                        uint32_t tok,
                        uint64_t now_us,
                        ash_ep_t *tester_main,
                        ash_ep_t *peer_ep,
                        uint64_t *peer_tcp_conn);

/* Fast-path zero-decryption packet relay (mutates pkt[5..8] to zero token before egress) */
ash_relay_route_t ash_relay_on_packet(ash_relay_table_t *rt,
                                      uint8_t *pkt,
                                      size_t pkt_len,
                                      const ash_ep_t *from_ep,
                                      uint64_t from_tcp_conn,
                                      uint64_t now_us,
                                      uint32_t now_wall_min);

void     ash_relay_on_tcp_closed(ash_relay_table_t *rt, uint64_t tcp_conn_id);
void     ash_relay_sweep_step(ash_relay_table_t *rt, uint64_t now_us);
uint32_t ash_relay_active_sessions(ash_relay_table_t *rt, uint64_t now_us);
size_t   ash_relay_memory_bytes(const ash_relay_table_t *rt);

#ifdef __cplusplus
}
#endif

#endif /* ASH_RELAY_H */
