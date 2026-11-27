#ifndef ASH_SERVER_H
#define ASH_SERVER_H

#include "ash_common.h"
#include "ash_ratelimit.h"
#include "ash_registry.h"
#include "ash_relay.h"
#include "ash_wire.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    ASH_MODE_ALL   = 0,  /* All-in-One: Signaling (ID/Rendezvous) + Relay/TURN */
    ASH_MODE_ID    = 1,  /* Standalone Signaling / ID Server */
    ASH_MODE_RELAY = 2   /* Standalone Edge Relay / TURN Server */
} ash_server_mode_t;

typedef enum {
    ASH_COOKIE_ADAPTIVE = 0, /* Require UDP cookie only when unauth signaling exceeds threshold */
    ASH_COOKIE_ALWAYS   = 1, /* Always require stateless source-IP cookie on v2 UDP */
    ASH_COOKIE_OFF      = 2  /* Disabled */
} ash_cookie_policy_t;

typedef struct {
    ash_server_mode_t   mode;
    const char         *bind_ip;          /* Default "::" (dual-stack IPv4 + IPv6) */
    uint16_t            udp_port;         /* Primary UDP signaling/relay port (default 44200, 0=auto) */
    bool                enable_nat_probe; /* Bind udp_port + 1 for Cone/Symmetric NAT detection */
    uint16_t            tcp_port;         /* TCP 443 fallback port (0 = disabled) */
    uint16_t            metrics_port;     /* Optional HTTP /metrics & /healthz port (0 = disabled) */
    const char         *metrics_bind_ip;  /* Default "127.0.0.1" */

    uint32_t            num_workers;      /* 0 = auto */
    uint32_t            max_hosts;        /* Default 65536 */
    uint32_t            max_sessions;     /* Default 65536 */
    uint32_t            max_tcp_conns;    /* Default 8192 */

    bool                allow_v1_unauth;  /* Backward compatibility with AshDesk adp_rdv v1 */
    ash_cookie_policy_t cookie_policy;
    uint32_t            cookie_flood_pps; /* Adaptive cookie trigger threshold (default 500 pps) */
    uint16_t            ip_sig_rps;       /* Max signaling packets/sec per IP (default 80) */
    uint16_t            ip_max_strikes;   /* Max bad auth/token strikes before block (default 12) */
    uint16_t            ip_new_numbers_per_day; /* AshDesk numbers one source may newly claim per day (default 300, 0 = no limit) */

    uint64_t            host_ttl_sec;     /* Default 60 */
    uint64_t            sess_ttl_sec;     /* Default 120 */
    const char         *keystore_path;    /* Optional persistent Ed25519 device pin store */

    /* Commercial QoS Bandwidth Tiers (kbps, 0 = unlimited) */
    uint32_t            free_kbps;        /* Default 2000 (2 Mbps) or 0 if unthrottled */
    uint32_t            pro_kbps;         /* Default 20000 (20 Mbps) */
    uint32_t            vip_kbps;         /* Default 100000 (100 Mbps) */
    uint32_t            dedicated_kbps;   /* Default 0 (unlimited) */
    uint32_t            free_pool_kbps;   /* Aggregate cap for all FREE sessions */
    uint32_t            total_bw_kbps;    /* Aggregate cap for entire Relay node */

    /* Cluster & Public Endpoint Advertisement */
    uint8_t             cluster_secret[32];
    uint8_t             license_secret[32];
    uint32_t            node_id;          /* Unique Relay node ID in distributed mode */
    uint8_t             node_tier_max;    /* Max tier served by this Relay node */
    uint16_t            node_pool_id;     /* 0 = shared pool, >0 = dedicated enterprise pool */
    uint16_t            region_id;
    ash_ep_t            public_udp_ep;    /* Advertised public UDP endpoint for Relay */
    ash_ep_t            public_tcp_ep;    /* Advertised public TCP 443 endpoint for Relay */
    ash_ep_t            upstream_id_ep;   /* In ASH_MODE_RELAY: ID server UDP endpoint for heartbeats */
} ash_server_cfg_t;

typedef struct ash_server_s ash_server_t;

void          ash_server_cfg_defaults(ash_server_cfg_t *cfg);
ash_server_t *ash_server_create(const ash_server_cfg_t *cfg);
bool          ash_server_start(ash_server_t *srv);
void          ash_server_stop(ash_server_t *srv);
void          ash_server_destroy(ash_server_t *srv);

/* Runtime inspection helpers (for CLI telemetry, /metrics, and E2E tests) */
uint16_t ash_server_udp_port(const ash_server_t *srv);
uint16_t ash_server_probe_port(const ash_server_t *srv);
uint16_t ash_server_tcp_port(const ash_server_t *srv);
uint16_t ash_server_metrics_port(const ash_server_t *srv);
size_t   ash_server_allocated_bytes(const ash_server_t *srv);
size_t   ash_server_format_metrics(ash_server_t *srv, char *buf, size_t cap);

#ifdef __cplusplus
}
#endif

#endif /* ASH_SERVER_H */
