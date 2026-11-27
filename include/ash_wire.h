#ifndef ASH_WIRE_H
#define ASH_WIRE_H

#include "ash_common.h"
#include "ash_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Wire magic bytes — strictly non-overlapping with DTLS (0x14..0x19), full_v1 (0x41),
 * lan_v3 (0xC0+), Pairing (0x50), and STUN (0x00..0x03). */
#define ASH_SIG_MAGIC        0x53u  /* 'S': Signaling (v1 & v2) */
#define ASH_RELAY_MAGIC      0x52u  /* 'R': Zero-decryption media/control relay */
#define ASH_REJECT_MAGIC     0x4Au  /* 'J': Explicit reject notification */
#define ASH_EXT_MAGIC        0xE1u  /* v1 trailing extension marker */
#define ASH_OWN_EXT          0xE2u  /* v1 REG trailing ownership proof: pub[32] | nonce[8] | sig[64] */
#define ASH_OWN_NONCE_LEN    8u
#define ASH_OWN_EXT_BYTES    (1u + ASH_ED25519_PUB_LEN + ASH_OWN_NONCE_LEN + ASH_ED25519_SIG_LEN)

#define ASH_RELAY_HDR_BYTES  9u
#define ASH_MAX_CANDS        8u
#define ASH_MAX_NAME_LEN     63u
#define ASH_COOKIE_LEN       16u
#define ASH_LICENSE_BYTES    40u
#define ASH_TICKET_BYTES     36u
#define ASH_MAX_FRAME_PAYLOAD 2048u

#define ASH_DEFAULT_UDP_PORT 44200u
#define ASH_DEFAULT_TCP_PORT 443u

/* Host capability & readiness flags (compatible with adp_rdv.h RDV_HF_*) */
#define ASH_HF_DTLS_READY    0x01u
#define ASH_HF_CAP_OK        0x02u
#define ASH_HF_BUSY          0x04u
#define ASH_HF_ATTENDED      0x08u
#define ASH_HF_PASSWORD      0x10u  /* AshDesk RDV_HF_PASSWORD: host accepts connection passwords (passed through untouched) */
#define ASH_HF_TCP_PUNCH     0x20u  /* Was 0x10 until AshDesk took that bit for RDV_HF_PASSWORD; no deployed host ever set it */

/* Commercial QoS / Bandwidth Tiers */
typedef enum {
    ASH_TIER_FREE      = 0,  /* Free public relay (rate-limited, e.g. 2 Mbps) */
    ASH_TIER_PRO       = 1,  /* Paid High-Speed channel (e.g. 20 Mbps) */
    ASH_TIER_VIP       = 2,  /* Paid Ultra/4K lossless channel (e.g. 100 Mbps) */
    ASH_TIER_DEDICATED = 3   /* Enterprise / Dedicated private node pool */
} ash_tier_t;

/* Detected NAT Mapping Behavior */
typedef enum {
    ASH_NAT_UNKNOWN    = 0,
    ASH_NAT_OPEN_CONE  = 1,  /* Endpoint-Independent Mapping (UDP punch high success) */
    ASH_NAT_SYMMETRIC  = 2,  /* Endpoint-Dependent Mapping (hard UDP punch -> Relay/TCP) */
    ASH_NAT_UDP_BLOCKED = 3  /* Corporate firewall blocking UDP -> TCP 443 fallback */
} ash_nat_type_t;

/* Coordinated NAT Hole-Punching Strategy */
typedef enum {
    ASH_PUNCH_LAN_DIRECT      = 1,  /* Same LAN / private candidates available */
    ASH_PUNCH_UDP_CONE        = 2,  /* At least one side has Endpoint-Independent NAT */
    ASH_PUNCH_UDP_SYM_PREDICT = 3,  /* Symmetric NAT with sequential port delta hint */
    ASH_PUNCH_TCP_SIMUL       = 4,  /* UDP blocked or dual Symmetric -> TCP simultaneous open */
    ASH_PUNCH_RELAY_ONLY      = 5   /* Immediate Relay fallback (no direct P2P viable) */
} ash_punch_strategy_t;

/* Message types inside 'S' (0x53) namespace */
typedef enum {
    /* v1 (100% compatible with D:\Code\AshDesk\proto\common\adp_rdv.h) */
    ASH_RDV1_REG             = 1,
    ASH_RDV1_REG_OK          = 2,
    ASH_RDV1_LOOKUP          = 3,
    ASH_RDV1_CONN            = 4,
    ASH_RDV1_INCOMING        = 5,
    ASH_RDV1_NOTFOUND        = 6,
    /* NAT mapping test: NAT_TEST req | sess tok goes to the main port (req 1) and the probe port (req 2); NAT_OK
     * req | observed address answers on the same port. A probe-port test with a live session's sess and token also
     * sends the other side NAT_PEER sess | 2 cands (tester's main-port and probe-port mappings) from the main port,
     * which a symmetric NAT on the tester's side needs for port prediction. */
    ASH_RDV1_NAT_TEST        = 7,
    ASH_RDV1_NAT_OK          = 8,
    ASH_RDV1_NAT_PEER        = 9,
    /* Presence (AshDesk M1): req | name -> PRESENCE_OK req | host_flags u8, or NOTFOUND. No session, host not notified.
     * host_flags is a body byte (not the 6 B trailing extension) so both replies stay shorter than the >= 8 B request. */
    ASH_RDV1_PRESENCE        = 10,
    ASH_RDV1_PRESENCE_OK     = 11,
    /* Number ownership (AshDesk docs/号码连接设计.md §4.2). A 9-digit name must be proved: the server answers a REG
     * that carries no valid proof with REG_CHAL nonce[8]; the host repeats the REG with the trailing extension
     * 0xE2 | pub[32] | nonce[8] | sig[64], sig = Ed25519 over "AshDesk number v1" | nonce | name. A number belongs to
     * the first key that registers it; another key gets REG_TAKEN name. Keepalives from the unchanged address carry
     * no proof. Both replies are shorter than the REG that triggers them. */
    ASH_RDV1_REG_CHAL        = 12,
    ASH_RDV1_REG_TAKEN       = 13,

    /* v2 Production Authenticated Signaling & Cluster Control */
    ASH_MSG_COOKIE_CHALLENGE = 0x10,
    ASH_MSG_REG_V2           = 0x11,
    ASH_MSG_REG_OK_V2        = 0x12,
    ASH_MSG_NAT_PROBE        = 0x13,
    ASH_MSG_NAT_PROBE_RSP    = 0x14,
    ASH_MSG_LOOKUP_V2        = 0x15,
    ASH_MSG_CONN_V2          = 0x16,
    ASH_MSG_INCOMING_V2      = 0x17,
    ASH_MSG_UNREG_V2         = 0x18,
    ASH_MSG_RELAY_BIND_V2    = 0x19,
    ASH_MSG_RELAY_BIND_OK    = 0x1A,
    ASH_MSG_NODE_HB          = 0x1E
} ash_msg_type_t;

/* v2 Registration Status Codes */
typedef enum {
    ASH_STATUS_OK              = 0,
    ASH_STATUS_AUTH_FAILED     = 1,  /* Ed25519 signature invalid or ID owned by another key */
    ASH_STATUS_COOKIE_REQUIRED = 2,
    ASH_STATUS_BAD_LICENSE     = 3,
    ASH_STATUS_RATE_LIMITED    = 4,
    ASH_STATUS_CAPACITY_FULL   = 5,
    ASH_STATUS_REPLAY_REJECTED = 6
} ash_status_t;

/* ---------------- v1 Compatible Message ---------------- */
typedef struct {
    uint8_t  type;
    uint32_t req;
    uint32_t sess;
    uint32_t tok;
    char     name[ASH_MAX_NAME_LEN + 1u];
    uint8_t  ncand;
    ash_ep_t cand[ASH_MAX_CANDS];
    uint8_t  host_flags;
    uint32_t relay_max_kbps;
    /* Number ownership: REG carries pub / nonce / sig when has_own = 1; REG_CHAL carries own_nonce only */
    uint8_t  has_own;
    uint8_t  own_pub[ASH_ED25519_PUB_LEN];
    uint8_t  own_nonce[ASH_OWN_NONCE_LEN];
    uint8_t  own_sig[ASH_ED25519_SIG_LEN];
} ash_rdv1_msg_t;

size_t ash_rdv1_build(uint8_t *out, size_t cap, const ash_rdv1_msg_t *m);
bool   ash_rdv1_parse(const uint8_t *buf, size_t len, ash_rdv1_msg_t *out);
/* Value of a 9-digit AshDesk number (first digit 1-9), or 0 when the name is not a number */
uint32_t ash_rdv1_number_value(const char *name);
/* Ownership proof: Ed25519 over "AshDesk number v1" | nonce | name. Sign fills has_own / own_pub / own_nonce / own_sig
 * (false for an empty or over-long name); verify needs has_own = 1. */
bool ash_rdv1_own_sign(ash_rdv1_msg_t *reg, const uint8_t nonce[ASH_OWN_NONCE_LEN],
                       const uint8_t ed25519_pub[ASH_ED25519_PUB_LEN],
                       const uint8_t ed25519_secret[ASH_ED25519_SEC_LEN]);
bool ash_rdv1_own_verify(const ash_rdv1_msg_t *reg);

/* ---------------- Relay Packet Framing ('R') ---------------- */
size_t ash_relay_wrap(uint8_t *out, size_t cap, uint32_t sess, uint32_t tok,
                      const uint8_t *payload, size_t payload_len);
size_t ash_relay_unwrap(const uint8_t *buf, size_t len, uint32_t *sess, uint32_t *tok);

/* ---------------- Commercial License Token (40B) ---------------- */
typedef struct {
    uint8_t  tier;          /* ash_tier_t */
    uint16_t pool_id;       /* 0 = shared pool, >0 = dedicated enterprise pool */
    uint32_t max_kbps;      /* 0 = tier default, >0 = explicit per-session kbps */
    uint64_t expire_ms;     /* 0 = perpetual, >0 = UTC epoch ms */
    uint32_t subject_hash;  /* 0 = any device, >0 = bound to ash_device_hash32(name) */
} ash_license_claims_t;

uint32_t ash_device_hash32(const char *device_name);
void     ash_license_sign(const uint8_t license_secret[32],
                          const ash_license_claims_t *claims,
                          uint8_t out_raw[ASH_LICENSE_BYTES]);
bool     ash_license_verify(const uint8_t license_secret[32],
                            const uint8_t raw[ASH_LICENSE_BYTES],
                            const char *expected_device_or_null,
                            uint64_t now_wall_ms,
                            ash_license_claims_t *out_claims);

/* ---------------- Stateless Cluster Relay Ticket (36B) & Token Derivation ---------------- */
typedef struct {
    uint8_t  tier;
    uint16_t pool_id;
    uint32_t sess;
    uint32_t max_kbps;
    uint32_t issue_sec;
    uint16_t ttl_sec;
    uint16_t flags;
} ash_ticket_claims_t;

void     ash_ticket_sign(const uint8_t cluster_secret[32],
                         const ash_ticket_claims_t *claims,
                         uint8_t out_raw[ASH_TICKET_BYTES]);
bool     ash_ticket_verify(const uint8_t cluster_secret[32],
                           const uint8_t raw[ASH_TICKET_BYTES],
                           uint32_t now_wall_sec,
                           ash_ticket_claims_t *out_claims);

uint32_t ash_make_sess_id(uint8_t tier, uint32_t now_min, uint32_t seq22);
void     ash_derive_sess_tokens(const uint8_t cluster_secret[32],
                                uint32_t sess,
                                uint32_t *out_tok_host,
                                uint32_t *out_tok_client);
bool     ash_verify_stateless_relay_tok(const uint8_t cluster_secret[32],
                                        uint32_t sess,
                                        uint32_t tok,
                                        uint32_t now_min,
                                        uint32_t max_age_min,
                                        bool *out_is_host,
                                        uint8_t *out_tier);

/* ---------------- v2 Messages ---------------- */
typedef struct {
    uint8_t orig_type;
    uint8_t cookie[ASH_COOKIE_LEN];
} ash_msg_challenge_t;

size_t ash_build_challenge(uint8_t *out, size_t cap, const ash_msg_challenge_t *m);
bool   ash_parse_challenge(const uint8_t *buf, size_t len, ash_msg_challenge_t *out);

typedef struct {
    uint8_t  flags;
    uint8_t  nat_type;
    uint8_t  host_flags;
    uint16_t tcp_port;
    uint64_t ts_ms;
    uint8_t  cookie[ASH_COOKIE_LEN];
    uint8_t  pubkey[ASH_ED25519_PUB_LEN];
    uint8_t  sig[ASH_ED25519_SIG_LEN];
    char     name[ASH_MAX_NAME_LEN + 1u];
    uint8_t  ncand;
    ash_ep_t cand[ASH_MAX_CANDS];
    bool     has_license;
    uint8_t  license[ASH_LICENSE_BYTES];
} ash_msg_reg_v2_t;

void   ash_reg_v2_sign(ash_msg_reg_v2_t *m, const uint8_t ed25519_secret[ASH_ED25519_SEC_LEN]);
bool   ash_reg_v2_verify_sig(const ash_msg_reg_v2_t *m);
size_t ash_build_reg_v2(uint8_t *out, size_t cap, const ash_msg_reg_v2_t *m);
bool   ash_parse_reg_v2(const uint8_t *buf, size_t len, ash_msg_reg_v2_t *out);

typedef struct {
    uint8_t  status;
    uint8_t  tier;
    uint16_t probe_port;
    uint16_t hb_sec;
    ash_ep_t obs;
} ash_msg_reg_ok_v2_t;

size_t ash_build_reg_ok_v2(uint8_t *out, size_t cap, const ash_msg_reg_ok_v2_t *m);
bool   ash_parse_reg_ok_v2(const uint8_t *buf, size_t len, ash_msg_reg_ok_v2_t *out);

size_t ash_build_nat_probe(uint8_t *out, size_t cap, uint32_t nonce);
bool   ash_parse_nat_probe(const uint8_t *buf, size_t len, uint32_t *out_nonce);
size_t ash_build_nat_probe_rsp(uint8_t *out, size_t cap, uint32_t nonce, const ash_ep_t *obs);
bool   ash_parse_nat_probe_rsp(const uint8_t *buf, size_t len, uint32_t *out_nonce, ash_ep_t *out_obs);

typedef struct {
    uint8_t  flags;
    uint8_t  client_nat;
    uint8_t  prefer_tcp;
    uint16_t pool_id;
    uint32_t req;
    uint8_t  cookie[ASH_COOKIE_LEN];
    char     name[ASH_MAX_NAME_LEN + 1u];
    uint8_t  ncand;
    ash_ep_t cand[ASH_MAX_CANDS];
    bool     has_license;
    uint8_t  license[ASH_LICENSE_BYTES];
} ash_msg_lookup_v2_t;

size_t ash_build_lookup_v2(uint8_t *out, size_t cap, const ash_msg_lookup_v2_t *m);
bool   ash_parse_lookup_v2(const uint8_t *buf, size_t len, ash_msg_lookup_v2_t *out);

typedef struct {
    uint8_t  type;            /* ASH_MSG_CONN_V2 or ASH_MSG_INCOMING_V2 */
    uint32_t req;
    uint32_t sess;
    uint32_t tok;
    uint8_t  punch_strategy;  /* ash_punch_strategy_t */
    uint16_t punch_sync_ms;   /* Synchronized simultaneous hole-punch delay */
    int16_t  port_stride;     /* Observed NAT port stride hint */
    uint8_t  peer_nat;
    uint8_t  host_flags;
    uint8_t  tier;
    uint32_t relay_max_kbps;
    ash_ep_t relay_udp;
    ash_ep_t relay_tcp;
    uint8_t  relay_ticket[ASH_TICKET_BYTES];
    uint8_t  ncand;
    ash_ep_t cand[ASH_MAX_CANDS];
} ash_msg_conn_v2_t;

size_t ash_build_conn_v2(uint8_t *out, size_t cap, const ash_msg_conn_v2_t *m);
bool   ash_parse_conn_v2(const uint8_t *buf, size_t len, ash_msg_conn_v2_t *out);

typedef struct {
    uint64_t ts_ms;
    uint8_t  pubkey[ASH_ED25519_PUB_LEN];
    uint8_t  sig[ASH_ED25519_SIG_LEN];
    char     name[ASH_MAX_NAME_LEN + 1u];
} ash_msg_unreg_v2_t;

void   ash_unreg_v2_sign(ash_msg_unreg_v2_t *m, const uint8_t ed25519_secret[ASH_ED25519_SEC_LEN]);
bool   ash_unreg_v2_verify_sig(const ash_msg_unreg_v2_t *m);
size_t ash_build_unreg_v2(uint8_t *out, size_t cap, const ash_msg_unreg_v2_t *m);
bool   ash_parse_unreg_v2(const uint8_t *buf, size_t len, ash_msg_unreg_v2_t *out);

typedef struct {
    uint8_t role; /* 1 = Host, 2 = Client */
    uint8_t ticket[ASH_TICKET_BYTES];
} ash_msg_relay_bind_t;

size_t ash_build_relay_bind(uint8_t *out, size_t cap, const ash_msg_relay_bind_t *m);
bool   ash_parse_relay_bind(const uint8_t *buf, size_t len, ash_msg_relay_bind_t *out);

typedef struct {
    uint8_t  status;
    uint32_t sess;
    uint32_t tok;
    uint32_t max_kbps;
} ash_msg_relay_bind_ok_t;

size_t ash_build_relay_bind_ok(uint8_t *out, size_t cap, const ash_msg_relay_bind_ok_t *m);
bool   ash_parse_relay_bind_ok(const uint8_t *buf, size_t len, ash_msg_relay_bind_ok_t *out);

/* Distributed Relay Node -> ID Server Cluster Heartbeat */
typedef struct {
    uint32_t node_id;
    uint8_t  tier_max;       /* Max tier supported or dedicated tier */
    uint16_t pool_id;        /* 0 = shared pool, >0 = dedicated enterprise pool */
    uint16_t region_id;
    uint32_t active_sessions;
    uint32_t used_kbps;
    uint32_t cap_kbps;
    uint64_t ts_ms;
    ash_ep_t public_udp;
    ash_ep_t public_tcp;
} ash_msg_node_hb_t;

size_t ash_build_node_hb(uint8_t *out, size_t cap,
                         const uint8_t cluster_secret[32],
                         const ash_msg_node_hb_t *m);
bool   ash_parse_node_hb(const uint8_t *buf, size_t len,
                         const uint8_t cluster_secret[32],
                         ash_msg_node_hb_t *out);

/* ---------------- TCP 443 Framing (RFC 4571 / TLS 1.2+ AppData / HTTP Upgrade) ---------------- */
typedef enum {
    ASH_TCP_FRAME_UNKNOWN = 0,
    ASH_TCP_FRAME_RFC4571 = 1,  /* [len_be16][payload] */
    ASH_TCP_FRAME_TLS_APP = 2   /* [0x17 0x03 0x03 len_be16][payload] */
} ash_tcp_frame_mode_t;

size_t ash_tcp_frame_encode(ash_tcp_frame_mode_t mode,
                            const uint8_t *payload, size_t payload_len,
                            uint8_t *out, size_t cap);

/* Incremental stream parser: returns >0 total frame bytes consumed from in[0..in_len] and sets
 * *out_payload / *out_payload_len; returns 0 if more bytes needed; returns -1 on malformed stream. */
int ash_tcp_frame_decode(ash_tcp_frame_mode_t *inout_mode,
                         const uint8_t *in, size_t in_len,
                         const uint8_t **out_payload, size_t *out_payload_len,
                         bool *out_need_http_101);

#ifdef __cplusplus
}
#endif

#endif /* ASH_WIRE_H */
