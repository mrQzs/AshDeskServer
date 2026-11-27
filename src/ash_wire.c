#include "ash_wire.h"

#include <string.h>

/* ---------------- Endpoint Wire Helpers ----------------
 * v1 cand format: fam (4 or 6) | ip (4 or 16) | port be16.
 * For v2 candidates that carry TCP candidates, bit 7 of fam (0x80) encodes TCP (proto=6) while
 * keeping UDP candidates (4 or 6) byte-identical to v1! */
static size_t ep_wire_len(uint8_t raw_fam) {
    uint8_t base = (uint8_t)(raw_fam & 0x7Fu);
    if (base == 4u) return 7u;
    if (base == 6u) return 19u;
    if (base == 0u) return 1u; /* Unset endpoint in v2 fixed fields */
    return 0u;
}

static size_t put_ep_v1(uint8_t *dst, size_t cap, const ash_ep_t *ep) {
    if ((ep->fam != 4u) && (ep->fam != 6u)) return 0u;
    size_t need = (ep->fam == 4u) ? 7u : 19u;
    if (cap < need) return 0u;
    dst[0] = ep->fam;
    size_t ip_len = need - 3u;
    memcpy(dst + 1u, ep->ip, ip_len);
    ash_put_be16(dst + 1u + ip_len, ep->port);
    return need;
}

static size_t get_ep_v1(const uint8_t *src, size_t rem, ash_ep_t *ep) {
    if (rem < 1u) return 0u;
    uint8_t fam = src[0];
    if ((fam != 4u) && (fam != 6u)) return 0u;
    size_t need = (fam == 4u) ? 7u : 19u;
    if (rem < need) return 0u;
    memset(ep, 0, sizeof(*ep));
    ep->fam   = fam;
    ep->proto = 17u;
    size_t ip_len = need - 3u;
    memcpy(ep->ip, src + 1u, ip_len);
    ep->port = ash_get_be16(src + 1u + ip_len);
    return need;
}

static size_t put_ep_v2(uint8_t *dst, size_t cap, const ash_ep_t *ep, bool allow_empty) {
    if ((ep == NULL) || (ep->fam == 0u)) {
        if (!allow_empty || (cap < 1u)) return 0u;
        dst[0] = 0u;
        return 1u;
    }
    if ((ep->fam != 4u) && (ep->fam != 6u)) return 0u;
    size_t need = (ep->fam == 4u) ? 7u : 19u;
    if (cap < need) return 0u;
    uint8_t wf = ep->fam;
    if (ep->proto == 6u) wf |= 0x80u;
    dst[0] = wf;
    size_t ip_len = need - 3u;
    memcpy(dst + 1u, ep->ip, ip_len);
    ash_put_be16(dst + 1u + ip_len, ep->port);
    return need;
}

static size_t get_ep_v2(const uint8_t *src, size_t rem, ash_ep_t *ep, bool allow_empty) {
    if (rem < 1u) return 0u;
    uint8_t wf = src[0];
    if (wf == 0u) {
        if (!allow_empty) return 0u;
        memset(ep, 0, sizeof(*ep));
        return 1u;
    }
    size_t need = ep_wire_len(wf);
    if ((need < 7u) || (rem < need)) return 0u;
    memset(ep, 0, sizeof(*ep));
    ep->fam   = (uint8_t)(wf & 0x7Fu);
    ep->proto = ((wf & 0x80u) != 0u) ? 6u : 17u;
    size_t ip_len = need - 3u;
    memcpy(ep->ip, src + 1u, ip_len);
    ep->port = ash_get_be16(src + 1u + ip_len);
    return need;
}

/* ---------------- v1 Compatible Codec (adp_rdv) ---------------- */
/* F1_HF: host_flags as a body byte; such messages carry no trailing extension.
 * F1_NONCE: the 8-byte ownership nonce as a body field. F1_OWN: may end with the ownership proof extension (REG only). */
enum { F1_REQ = 1, F1_ST = 2, F1_NAME = 4, F1_CAND = 8, F1_HF = 16, F1_NONCE = 32, F1_OWN = 64 };

static int rdv1_fields(uint8_t t) {
    switch (t) {
    case ASH_RDV1_REG:         return F1_NAME | F1_CAND | F1_OWN;
    case ASH_RDV1_REG_CHAL:    return F1_NONCE;
    case ASH_RDV1_REG_TAKEN:   return F1_NAME;
    case ASH_RDV1_REG_OK:      return F1_CAND;
    case ASH_RDV1_LOOKUP:      return F1_REQ | F1_NAME | F1_CAND;
    case ASH_RDV1_CONN:        return F1_REQ | F1_ST | F1_CAND;
    case ASH_RDV1_INCOMING:    return F1_ST | F1_CAND;
    case ASH_RDV1_NOTFOUND:    return F1_REQ;
    case ASH_RDV1_NAT_TEST:    return F1_REQ | F1_ST;
    case ASH_RDV1_NAT_OK:      return F1_REQ | F1_CAND;
    case ASH_RDV1_NAT_PEER:    return F1_ST | F1_CAND;
    case ASH_RDV1_PRESENCE:    return F1_REQ | F1_NAME;
    case ASH_RDV1_PRESENCE_OK: return F1_REQ | F1_HF;
    default:                   return 0;
    }
}

size_t ash_rdv1_build(uint8_t *out, size_t cap, const ash_rdv1_msg_t *m) {
    if ((out == NULL) || (m == NULL)) return 0u;
    int f = rdv1_fields(m->type);
    if (f == 0) return 0u;
    size_t nl = strlen(m->name);
    if (((f & F1_NAME) != 0) && ((nl == 0u) || (nl > ASH_MAX_NAME_LEN))) return 0u;
    if (m->ncand > ASH_MAX_CANDS) return 0u;

    uint8_t b[2u + 4u + 8u + 1u + ASH_MAX_NAME_LEN + 1u + (ASH_MAX_CANDS * 19u) + 6u + ASH_OWN_NONCE_LEN + ASH_OWN_EXT_BYTES];
    size_t n = 0u;
    b[n++] = ASH_SIG_MAGIC;
    b[n++] = m->type;

    if ((f & F1_REQ) != 0) {
        ash_put_be32(b + n, m->req);
        n += 4u;
    }
    if ((f & F1_ST) != 0) {
        ash_put_be32(b + n, m->sess);
        ash_put_be32(b + n + 4u, m->tok);
        n += 8u;
    }
    if ((f & F1_NAME) != 0) {
        b[n++] = (uint8_t)nl;
        memcpy(b + n, m->name, nl);
        n += nl;
    }
    if ((f & F1_CAND) != 0) {
        b[n++] = m->ncand;
        for (uint8_t i = 0u; i < m->ncand; ++i) {
            size_t cl = put_ep_v1(b + n, sizeof(b) - n, &m->cand[i]);
            if (cl == 0u) return 0u;
            n += cl;
        }
    }
    if ((f & F1_HF) != 0) {
        b[n++] = m->host_flags;
    } else if ((m->host_flags != 0u) || (m->relay_max_kbps != 0u)) {
        b[n]      = ASH_EXT_MAGIC;
        b[n + 1u] = m->host_flags;
        ash_put_be32(b + n + 2u, m->relay_max_kbps);
        n += 6u;
    }
    if ((f & F1_NONCE) != 0) {
        memcpy(b + n, m->own_nonce, ASH_OWN_NONCE_LEN);
        n += ASH_OWN_NONCE_LEN;
    }
    if (((f & F1_OWN) != 0) && (m->has_own != 0u)) {
        b[n] = ASH_OWN_EXT;
        memcpy(b + n + 1u, m->own_pub, ASH_ED25519_PUB_LEN);
        memcpy(b + n + 1u + ASH_ED25519_PUB_LEN, m->own_nonce, ASH_OWN_NONCE_LEN);
        memcpy(b + n + 1u + ASH_ED25519_PUB_LEN + ASH_OWN_NONCE_LEN, m->own_sig, ASH_ED25519_SIG_LEN);
        n += ASH_OWN_EXT_BYTES;
    }
    if (n > cap) return 0u;
    memcpy(out, b, n);
    return n;
}

uint32_t ash_rdv1_number_value(const char *name) {
    if (name == NULL) return 0u;
    size_t len = strlen(name);
    if ((len != 9u) || (name[0] == '0')) return 0u;
    uint32_t v = 0u;
    for (size_t i = 0u; i < len; ++i) {
        if ((name[i] < '0') || (name[i] > '9')) return 0u;
        v = (v * 10u) + (uint32_t)((uint8_t)name[i] - (uint8_t)'0');
    }
    return v;
}

/* The signed message of an ownership proof: "AshDesk number v1" (no NUL) | nonce | name. Returns its length, 0 for a bad name */
#define OWN_TAG_BYTES 17u
#define OWN_MSG_MAX   (OWN_TAG_BYTES + ASH_OWN_NONCE_LEN + ASH_MAX_NAME_LEN)

static size_t own_message(const ash_rdv1_msg_t *reg, uint8_t msg[OWN_MSG_MAX]) {
    static const uint8_t tag[OWN_TAG_BYTES] = { 'A', 's', 'h', 'D', 'e', 's', 'k', ' ', 'n', 'u', 'm', 'b', 'e', 'r', ' ', 'v', '1' };
    size_t nl = strlen(reg->name);
    if ((nl == 0u) || (nl > ASH_MAX_NAME_LEN)) return 0u;
    size_t n = sizeof(tag);
    memcpy(msg, tag, sizeof(tag));
    memcpy(msg + n, reg->own_nonce, ASH_OWN_NONCE_LEN);
    n += ASH_OWN_NONCE_LEN;
    for (size_t i = 0u; i < nl; ++i) {
        msg[n + i] = (uint8_t)reg->name[i];
    }
    return n + nl;
}

bool ash_rdv1_own_sign(ash_rdv1_msg_t *reg, const uint8_t nonce[ASH_OWN_NONCE_LEN],
                       const uint8_t ed25519_pub[ASH_ED25519_PUB_LEN],
                       const uint8_t ed25519_secret[ASH_ED25519_SEC_LEN]) {
    if ((reg == NULL) || (nonce == NULL) || (ed25519_pub == NULL) || (ed25519_secret == NULL)) return false;
    uint8_t msg[OWN_MSG_MAX];
    memcpy(reg->own_nonce, nonce, ASH_OWN_NONCE_LEN);
    size_t n = own_message(reg, msg);
    if (n == 0u) return false;
    memcpy(reg->own_pub, ed25519_pub, ASH_ED25519_PUB_LEN);
    ash_ed25519_sign(ed25519_secret, msg, n, reg->own_sig);
    reg->has_own = 1u;
    return true;
}

bool ash_rdv1_own_verify(const ash_rdv1_msg_t *reg) {
    if ((reg == NULL) || (reg->has_own == 0u)) return false;
    uint8_t msg[OWN_MSG_MAX];
    size_t n = own_message(reg, msg);
    return (n != 0u) && ash_ed25519_verify(reg->own_pub, msg, n, reg->own_sig);
}

bool ash_rdv1_parse(const uint8_t *buf, size_t len, ash_rdv1_msg_t *out) {
    if ((buf == NULL) || (out == NULL) || (len < 2u) || (buf[0] != ASH_SIG_MAGIC)) return false;
    memset(out, 0, sizeof(*out));
    out->type = buf[1];
    int f = rdv1_fields(out->type);
    if (f == 0) return false;

    size_t o = 2u;
    if ((f & F1_REQ) != 0) {
        if ((o + 4u) > len) return false;
        out->req = ash_get_be32(buf + o);
        o += 4u;
    }
    if ((f & F1_ST) != 0) {
        if ((o + 8u) > len) return false;
        out->sess = ash_get_be32(buf + o);
        out->tok  = ash_get_be32(buf + o + 4u);
        o += 8u;
    }
    if ((f & F1_NAME) != 0) {
        if (o >= len) return false;
        uint8_t nl = buf[o++];
        if ((nl == 0u) || (nl > ASH_MAX_NAME_LEN) || ((o + nl) > len)) return false;
        memcpy(out->name, buf + o, nl);
        out->name[nl] = '\0';
        o += nl;
    }
    if ((f & F1_CAND) != 0) {
        if (o >= len) return false;
        uint8_t nc = buf[o++];
        if (nc > ASH_MAX_CANDS) return false;
        out->ncand = nc;
        for (uint8_t i = 0u; i < nc; ++i) {
            size_t cl = get_ep_v1(buf + o, len - o, &out->cand[i]);
            if (cl == 0u) return false;
            o += cl;
        }
    }
    if ((f & F1_HF) != 0) {
        if (o >= len) return false;
        out->host_flags = buf[o++];
    } else if (((o + 6u) <= len) && (buf[o] == ASH_EXT_MAGIC)) {
        out->host_flags     = buf[o + 1u];
        out->relay_max_kbps = ash_get_be32(buf + o + 2u);
        o += 6u;
    }
    if ((f & F1_NONCE) != 0) {
        if ((o + ASH_OWN_NONCE_LEN) > len) return false;
        memcpy(out->own_nonce, buf + o, ASH_OWN_NONCE_LEN);
        o += ASH_OWN_NONCE_LEN;
    }
    if (((f & F1_OWN) != 0) && ((o + ASH_OWN_EXT_BYTES) == len) && (buf[o] == ASH_OWN_EXT)) {
        out->has_own = 1u;
        memcpy(out->own_pub, buf + o + 1u, ASH_ED25519_PUB_LEN);
        memcpy(out->own_nonce, buf + o + 1u + ASH_ED25519_PUB_LEN, ASH_OWN_NONCE_LEN);
        memcpy(out->own_sig, buf + o + 1u + ASH_ED25519_PUB_LEN + ASH_OWN_NONCE_LEN, ASH_ED25519_SIG_LEN);
        o += ASH_OWN_EXT_BYTES;
    }
    return o == len;   /* Unrecognized trailing bytes: reject the whole datagram */
}

/* ---------------- Relay Packet Wrap / Unwrap ---------------- */
size_t ash_relay_wrap(uint8_t *out, size_t cap, uint32_t sess, uint32_t tok,
                      const uint8_t *payload, size_t payload_len) {
    if ((out == NULL) || (payload == NULL) || (payload_len == 0u)) return 0u;
    if ((ASH_RELAY_HDR_BYTES + payload_len) > cap) return 0u;
    out[0] = ASH_RELAY_MAGIC;
    ash_put_be32(out + 1u, sess);
    ash_put_be32(out + 5u, tok);
    memmove(out + ASH_RELAY_HDR_BYTES, payload, payload_len);
    return ASH_RELAY_HDR_BYTES + payload_len;
}

size_t ash_relay_unwrap(const uint8_t *buf, size_t len, uint32_t *sess, uint32_t *tok) {
    if ((buf == NULL) || (len <= ASH_RELAY_HDR_BYTES) || (buf[0] != ASH_RELAY_MAGIC)) return 0u;
    if (sess != NULL) *sess = ash_get_be32(buf + 1u);
    if (tok != NULL)  *tok  = ash_get_be32(buf + 5u);
    return len - ASH_RELAY_HDR_BYTES;
}

/* ---------------- Commercial License Token & Stateless Relay Ticket ---------------- */
uint32_t ash_device_hash32(const char *device_name) {
    if ((device_name == NULL) || (device_name[0] == '\0')) return 0u;
    static const uint8_t k_fixed_key[16] = {
        'A', 's', 'h', 'D', 'e', 's', 'k', 'D', 'e', 'v', 'H', 'a', 's', 'h', 'v', '1'
    };
    uint64_t h = ash_siphash24(k_fixed_key, device_name, strlen(device_name));
    uint32_t h32 = (uint32_t)(h ^ (h >> 32u));
    return (h32 != 0u) ? h32 : 1u;
}

void ash_license_sign(const uint8_t license_secret[32],
                      const ash_license_claims_t *claims,
                      uint8_t out_raw[ASH_LICENSE_BYTES]) {
    out_raw[0] = (uint8_t)'A';
    out_raw[1] = (uint8_t)'S';
    out_raw[2] = (uint8_t)'H';
    out_raw[3] = (uint8_t)'L';
    out_raw[4] = 1u;
    out_raw[5] = claims->tier;
    ash_put_be16(out_raw + 6u, claims->pool_id);
    ash_put_be32(out_raw + 8u, claims->max_kbps);
    ash_put_be64(out_raw + 12u, claims->expire_ms);
    ash_put_be32(out_raw + 20u, claims->subject_hash);

    uint8_t mac[ASH_SHA256_BYTES];
    ash_hmac_sha256(license_secret, 32u, out_raw, 24u, mac);
    memcpy(out_raw + 24u, mac, 16u);
    ash_secure_zero(mac, sizeof(mac));
}

bool ash_license_verify(const uint8_t license_secret[32],
                        const uint8_t raw[ASH_LICENSE_BYTES],
                        const char *expected_device_or_null,
                        uint64_t now_wall_ms,
                        ash_license_claims_t *out_claims) {
    if ((license_secret == NULL) || (raw == NULL)) return false;
    if ((raw[0] != (uint8_t)'A') || (raw[1] != (uint8_t)'S') ||
        (raw[2] != (uint8_t)'H') || (raw[3] != (uint8_t)'L') || (raw[4] != 1u)) {
        return false;
    }
    if (raw[5] > (uint8_t)ASH_TIER_DEDICATED) return false;

    uint8_t mac[ASH_SHA256_BYTES];
    ash_hmac_sha256(license_secret, 32u, raw, 24u, mac);
    bool mac_ok = ash_ct_equal(mac, raw + 24u, 16u);
    ash_secure_zero(mac, sizeof(mac));
    if (!mac_ok) return false;

    ash_license_claims_t c;
    c.tier         = raw[5];
    c.pool_id      = ash_get_be16(raw + 6u);
    c.max_kbps     = ash_get_be32(raw + 8u);
    c.expire_ms    = ash_get_be64(raw + 12u);
    c.subject_hash = ash_get_be32(raw + 20u);

    if ((c.expire_ms != 0ULL) && (now_wall_ms > c.expire_ms)) {
        return false;
    }
    if ((c.subject_hash != 0u) && (expected_device_or_null != NULL) && (expected_device_or_null[0] != '\0')) {
        if (ash_device_hash32(expected_device_or_null) != c.subject_hash) {
            return false;
        }
    }
    if (out_claims != NULL) *out_claims = c;
    return true;
}

void ash_ticket_sign(const uint8_t cluster_secret[32],
                     const ash_ticket_claims_t *claims,
                     uint8_t out_raw[ASH_TICKET_BYTES]) {
    out_raw[0] = 1u;
    out_raw[1] = claims->tier;
    ash_put_be16(out_raw + 2u, claims->pool_id);
    ash_put_be32(out_raw + 4u, claims->sess);
    ash_put_be32(out_raw + 8u, claims->max_kbps);
    ash_put_be32(out_raw + 12u, claims->issue_sec);
    ash_put_be16(out_raw + 16u, claims->ttl_sec);
    ash_put_be16(out_raw + 18u, claims->flags);

    ash_hmac_sha256_ctx ctx;
    ash_hmac_sha256_init(&ctx, cluster_secret, 32u);
    ash_hmac_sha256_update(&ctx, "ASH-TICKET-V1", 13u);
    ash_hmac_sha256_update(&ctx, out_raw, 20u);
    uint8_t mac[ASH_SHA256_BYTES];
    ash_hmac_sha256_final(&ctx, mac);
    memcpy(out_raw + 20u, mac, 16u);
    ash_secure_zero(mac, sizeof(mac));
}

bool ash_ticket_verify(const uint8_t cluster_secret[32],
                       const uint8_t raw[ASH_TICKET_BYTES],
                       uint32_t now_wall_sec,
                       ash_ticket_claims_t *out_claims) {
    if ((cluster_secret == NULL) || (raw == NULL) || (raw[0] != 1u)) return false;
    if (raw[1] > (uint8_t)ASH_TIER_DEDICATED) return false;

    ash_hmac_sha256_ctx ctx;
    ash_hmac_sha256_init(&ctx, cluster_secret, 32u);
    ash_hmac_sha256_update(&ctx, "ASH-TICKET-V1", 13u);
    ash_hmac_sha256_update(&ctx, raw, 20u);
    uint8_t mac[ASH_SHA256_BYTES];
    ash_hmac_sha256_final(&ctx, mac);
    bool ok = ash_ct_equal(mac, raw + 20u, 16u);
    ash_secure_zero(mac, sizeof(mac));
    if (!ok) return false;

    ash_ticket_claims_t c;
    c.tier      = raw[1];
    c.pool_id   = ash_get_be16(raw + 2u);
    c.sess      = ash_get_be32(raw + 4u);
    c.max_kbps  = ash_get_be32(raw + 8u);
    c.issue_sec = ash_get_be32(raw + 12u);
    c.ttl_sec   = ash_get_be16(raw + 16u);
    c.flags     = ash_get_be16(raw + 18u);
    if (c.sess == 0u) return false;

    if ((c.ttl_sec != 0u) && (now_wall_sec > (c.issue_sec + (uint32_t)c.ttl_sec))) {
        return false;
    }
    if (out_claims != NULL) *out_claims = c;
    return true;
}

/* Session ID layout (31-bit positive integer compatible with AshDesk's Win32 LONG):
 *   [31]     = 0 (always > 0 as signed int32_t)
 *   [30..29] = tier (0..3)
 *   [28..22] = issue_min & 0x7F (128-minute rolling window)
 *   [21..0]  = seq22 (non-zero 22-bit counter/random) */
uint32_t ash_make_sess_id(uint8_t tier, uint32_t now_min, uint32_t seq22) {
    uint32_t low = seq22 & 0x3FFFFFu;
    if (low == 0u) low = 1u;
    uint32_t t2 = ((uint32_t)tier) & 3u;
    uint32_t m7 = now_min & 0x7Fu;
    return (t2 << 29u) | (m7 << 22u) | low;
}

void ash_derive_sess_tokens(const uint8_t cluster_secret[32],
                            uint32_t sess,
                            uint32_t *out_tok_host,
                            uint32_t *out_tok_client) {
    static const uint8_t k_tag[7] = { 'A', 'S', 'H', 'S', 'E', 'S', 'S' };
    uint8_t msg[11];
    memcpy(msg, k_tag, sizeof(k_tag));
    ash_put_be32(msg + 7u, sess);
    uint8_t mac[ASH_SHA256_BYTES];
    ash_hmac_sha256(cluster_secret, 32u, msg, sizeof(msg), mac);
    /* Bit 0 is always 1 (never 0); bit 1 distinguishes Host (0) vs Client (1); bit 31 is 0 */
    uint32_t th = (ash_get_be32(mac) & 0x7FFFFFFCu) | 0x1u;
    uint32_t tc = (ash_get_be32(mac + 4u) & 0x7FFFFFFCu) | 0x3u;
    ash_secure_zero(mac, sizeof(mac));
    if (out_tok_host != NULL)   *out_tok_host   = th;
    if (out_tok_client != NULL) *out_tok_client = tc;
}

bool ash_verify_stateless_relay_tok(const uint8_t cluster_secret[32],
                                    uint32_t sess,
                                    uint32_t tok,
                                    uint32_t now_min,
                                    uint32_t max_age_min,
                                    bool *out_is_host,
                                    uint8_t *out_tier) {
    if ((sess == 0u) || (tok == 0u) || ((sess & 0x80000000u) != 0u)) return false;
    uint32_t m7  = (sess >> 22u) & 0x7Fu;
    uint32_t cur = now_min & 0x7Fu;
    /* Allow 1 minute clock skew forward */
    uint32_t age = (cur + 1u - m7) & 0x7Fu;
    if (age > (max_age_min + 1u)) return false;

    uint32_t th = 0u, tc = 0u;
    ash_derive_sess_tokens(cluster_secret, sess, &th, &tc);
    if ((tok != th) && (tok != tc)) return false;

    if (out_is_host != NULL) *out_is_host = (tok == th);
    if (out_tier != NULL)    *out_tier    = (uint8_t)((sess >> 29u) & 3u);
    return true;
}

/* ---------------- v2 Messages ---------------- */
size_t ash_build_challenge(uint8_t *out, size_t cap, const ash_msg_challenge_t *m) {
    if ((out == NULL) || (m == NULL) || (cap < 20u)) return 0u;
    out[0] = ASH_SIG_MAGIC;
    out[1] = (uint8_t)ASH_MSG_COOKIE_CHALLENGE;
    out[2] = m->orig_type;
    out[3] = 0u;
    memcpy(out + 4u, m->cookie, ASH_COOKIE_LEN);
    return 20u;
}

bool ash_parse_challenge(const uint8_t *buf, size_t len, ash_msg_challenge_t *out) {
    if ((buf == NULL) || (out == NULL) || (len != 20u)) return false;
    if ((buf[0] != ASH_SIG_MAGIC) || (buf[1] != (uint8_t)ASH_MSG_COOKIE_CHALLENGE)) return false;
    out->orig_type = buf[2];
    memcpy(out->cookie, buf + 4u, ASH_COOKIE_LEN);
    return true;
}

static size_t build_reg_v2_transcript(const ash_msg_reg_v2_t *m, uint8_t *out, size_t cap) {
    size_t nl = strlen(m->name);
    if ((nl == 0u) || (nl > ASH_MAX_NAME_LEN) || (m->ncand > ASH_MAX_CANDS)) return 0u;
    size_t pos = 0u;
    static const char k_dom[] = "AshDesk-REG-v2";
    if ((pos + 14u + 13u + ASH_COOKIE_LEN + 1u + nl + 1u) > cap) return 0u;
    memcpy(out + pos, k_dom, 14u);
    pos += 14u;
    out[pos++] = m->flags;
    out[pos++] = m->nat_type;
    out[pos++] = m->host_flags;
    ash_put_be16(out + pos, m->tcp_port);
    pos += 2u;
    ash_put_be64(out + pos, m->ts_ms);
    pos += 8u;
    memcpy(out + pos, m->cookie, ASH_COOKIE_LEN);
    pos += ASH_COOKIE_LEN;
    out[pos++] = (uint8_t)nl;
    memcpy(out + pos, m->name, nl);
    pos += nl;
    out[pos++] = m->ncand;
    for (uint8_t i = 0u; i < m->ncand; ++i) {
        size_t cl = put_ep_v2(out + pos, cap - pos, &m->cand[i], false);
        if (cl == 0u) return 0u;
        pos += cl;
    }
    if (m->has_license) {
        if ((pos + 1u + ASH_LICENSE_BYTES) > cap) return 0u;
        out[pos++] = ASH_LICENSE_BYTES;
        memcpy(out + pos, m->license, ASH_LICENSE_BYTES);
        pos += ASH_LICENSE_BYTES;
    } else {
        if ((pos + 1u) > cap) return 0u;
        out[pos++] = 0u;
    }
    return pos;
}

void ash_reg_v2_sign(ash_msg_reg_v2_t *m, const uint8_t ed25519_secret[ASH_ED25519_SEC_LEN]) {
    if ((m == NULL) || (ed25519_secret == NULL)) return;
    memcpy(m->pubkey, ed25519_secret + 32u, ASH_ED25519_PUB_LEN);
    uint8_t tr[512];
    size_t tr_len = build_reg_v2_transcript(m, tr, sizeof(tr));
    if (tr_len == 0u) return;
    ash_ed25519_sign(ed25519_secret, tr, tr_len, m->sig);
}

bool ash_reg_v2_verify_sig(const ash_msg_reg_v2_t *m) {
    if (m == NULL) return false;
    uint8_t tr[512];
    size_t tr_len = build_reg_v2_transcript(m, tr, sizeof(tr));
    if (tr_len == 0u) return false;
    return ash_ed25519_verify(m->pubkey, tr, tr_len, m->sig);
}

size_t ash_build_reg_v2(uint8_t *out, size_t cap, const ash_msg_reg_v2_t *m) {
    if ((out == NULL) || (m == NULL)) return 0u;
    size_t nl = strlen(m->name);
    if ((nl == 0u) || (nl > ASH_MAX_NAME_LEN) || (m->ncand > ASH_MAX_CANDS)) return 0u;

    uint8_t b[512];
    size_t n = 0u;
    b[n++] = ASH_SIG_MAGIC;
    b[n++] = (uint8_t)ASH_MSG_REG_V2;
    b[n++] = m->flags;
    b[n++] = m->nat_type;
    b[n++] = m->host_flags;
    ash_put_be16(b + n, m->tcp_port);
    n += 2u;
    ash_put_be64(b + n, m->ts_ms);
    n += 8u;
    memcpy(b + n, m->cookie, ASH_COOKIE_LEN);
    n += ASH_COOKIE_LEN;
    memcpy(b + n, m->pubkey, ASH_ED25519_PUB_LEN);
    n += ASH_ED25519_PUB_LEN;
    memcpy(b + n, m->sig, ASH_ED25519_SIG_LEN);
    n += ASH_ED25519_SIG_LEN;
    b[n++] = (uint8_t)nl;
    memcpy(b + n, m->name, nl);
    n += nl;
    b[n++] = m->ncand;
    for (uint8_t i = 0u; i < m->ncand; ++i) {
        size_t cl = put_ep_v2(b + n, sizeof(b) - n, &m->cand[i], false);
        if (cl == 0u) return 0u;
        n += cl;
    }
    if (m->has_license) {
        if ((n + 1u + ASH_LICENSE_BYTES) > sizeof(b)) return 0u;
        b[n++] = ASH_LICENSE_BYTES;
        memcpy(b + n, m->license, ASH_LICENSE_BYTES);
        n += ASH_LICENSE_BYTES;
    } else {
        if ((n + 1u) > sizeof(b)) return 0u;
        b[n++] = 0u;
    }
    if (n > cap) return 0u;
    memcpy(out, b, n);
    return n;
}

bool ash_parse_reg_v2(const uint8_t *buf, size_t len, ash_msg_reg_v2_t *out) {
    const size_t fixed_hdr = 2u + 3u + 2u + 8u + ASH_COOKIE_LEN + ASH_ED25519_PUB_LEN + ASH_ED25519_SIG_LEN;
    if ((buf == NULL) || (out == NULL) || (len < (fixed_hdr + 3u))) return false;
    if ((buf[0] != ASH_SIG_MAGIC) || (buf[1] != (uint8_t)ASH_MSG_REG_V2)) return false;

    memset(out, 0, sizeof(*out));
    size_t o = 2u;
    out->flags      = buf[o++];
    out->nat_type   = buf[o++];
    out->host_flags = buf[o++];
    out->tcp_port   = ash_get_be16(buf + o);
    o += 2u;
    out->ts_ms      = ash_get_be64(buf + o);
    o += 8u;
    memcpy(out->cookie, buf + o, ASH_COOKIE_LEN);
    o += ASH_COOKIE_LEN;
    memcpy(out->pubkey, buf + o, ASH_ED25519_PUB_LEN);
    o += ASH_ED25519_PUB_LEN;
    memcpy(out->sig, buf + o, ASH_ED25519_SIG_LEN);
    o += ASH_ED25519_SIG_LEN;

    uint8_t nl = buf[o++];
    if ((nl == 0u) || (nl > ASH_MAX_NAME_LEN) || ((o + nl + 1u) > len)) return false;
    memcpy(out->name, buf + o, nl);
    out->name[nl] = '\0';
    o += nl;

    uint8_t nc = buf[o++];
    if (nc > ASH_MAX_CANDS) return false;
    out->ncand = nc;
    for (uint8_t i = 0u; i < nc; ++i) {
        size_t cl = get_ep_v2(buf + o, len - o, &out->cand[i], false);
        if (cl == 0u) return false;
        o += cl;
    }

    if (o >= len) return false;
    uint8_t ll = buf[o++];
    if (ll == ASH_LICENSE_BYTES) {
        if ((o + ASH_LICENSE_BYTES) != len) return false;
        out->has_license = true;
        memcpy(out->license, buf + o, ASH_LICENSE_BYTES);
    } else if (ll == 0u) {
        if (o != len) return false;
        out->has_license = false;
    } else {
        return false;
    }
    return true;
}

size_t ash_build_reg_ok_v2(uint8_t *out, size_t cap, const ash_msg_reg_ok_v2_t *m) {
    if ((out == NULL) || (m == NULL) || (cap < 27u)) return 0u;
    size_t n = 0u;
    out[n++] = ASH_SIG_MAGIC;
    out[n++] = (uint8_t)ASH_MSG_REG_OK_V2;
    out[n++] = m->status;
    out[n++] = m->tier;
    ash_put_be16(out + n, m->probe_port);
    n += 2u;
    ash_put_be16(out + n, m->hb_sec);
    n += 2u;
    size_t cl = put_ep_v2(out + n, cap - n, &m->obs, true);
    if (cl == 0u) return 0u;
    return n + cl;
}

bool ash_parse_reg_ok_v2(const uint8_t *buf, size_t len, ash_msg_reg_ok_v2_t *out) {
    if ((buf == NULL) || (out == NULL) || (len < 9u)) return false;
    if ((buf[0] != ASH_SIG_MAGIC) || (buf[1] != (uint8_t)ASH_MSG_REG_OK_V2)) return false;
    memset(out, 0, sizeof(*out));
    out->status     = buf[2];
    out->tier       = buf[3];
    out->probe_port = ash_get_be16(buf + 4u);
    out->hb_sec     = ash_get_be16(buf + 6u);
    size_t cl = get_ep_v2(buf + 8u, len - 8u, &out->obs, true);
    return (cl > 0u) && ((8u + cl) == len);
}

size_t ash_build_nat_probe(uint8_t *out, size_t cap, uint32_t nonce) {
    if ((out == NULL) || (cap < 6u)) return 0u;
    out[0] = ASH_SIG_MAGIC;
    out[1] = (uint8_t)ASH_MSG_NAT_PROBE;
    ash_put_be32(out + 2u, nonce);
    return 6u;
}

bool ash_parse_nat_probe(const uint8_t *buf, size_t len, uint32_t *out_nonce) {
    if ((buf == NULL) || (len != 6u)) return false;
    if ((buf[0] != ASH_SIG_MAGIC) || (buf[1] != (uint8_t)ASH_MSG_NAT_PROBE)) return false;
    if (out_nonce != NULL) *out_nonce = ash_get_be32(buf + 2u);
    return true;
}

size_t ash_build_nat_probe_rsp(uint8_t *out, size_t cap, uint32_t nonce, const ash_ep_t *obs) {
    if ((out == NULL) || (obs == NULL) || (cap < 25u)) return 0u;
    out[0] = ASH_SIG_MAGIC;
    out[1] = (uint8_t)ASH_MSG_NAT_PROBE_RSP;
    ash_put_be32(out + 2u, nonce);
    size_t cl = put_ep_v2(out + 6u, cap - 6u, obs, false);
    return (cl > 0u) ? (6u + cl) : 0u;
}

bool ash_parse_nat_probe_rsp(const uint8_t *buf, size_t len, uint32_t *out_nonce, ash_ep_t *out_obs) {
    if ((buf == NULL) || (out_obs == NULL) || (len < 13u)) return false;
    if ((buf[0] != ASH_SIG_MAGIC) || (buf[1] != (uint8_t)ASH_MSG_NAT_PROBE_RSP)) return false;
    if (out_nonce != NULL) *out_nonce = ash_get_be32(buf + 2u);
    size_t cl = get_ep_v2(buf + 6u, len - 6u, out_obs, false);
    return (cl > 0u) && ((6u + cl) == len);
}

size_t ash_build_lookup_v2(uint8_t *out, size_t cap, const ash_msg_lookup_v2_t *m) {
    if ((out == NULL) || (m == NULL)) return 0u;
    size_t nl = strlen(m->name);
    if ((nl == 0u) || (nl > ASH_MAX_NAME_LEN) || (m->ncand > ASH_MAX_CANDS)) return 0u;

    uint8_t b[512];
    size_t n = 0u;
    b[n++] = ASH_SIG_MAGIC;
    b[n++] = (uint8_t)ASH_MSG_LOOKUP_V2;
    b[n++] = m->flags;
    b[n++] = m->client_nat;
    b[n++] = m->prefer_tcp;
    ash_put_be16(b + n, m->pool_id);
    n += 2u;
    ash_put_be32(b + n, m->req);
    n += 4u;
    memcpy(b + n, m->cookie, ASH_COOKIE_LEN);
    n += ASH_COOKIE_LEN;
    b[n++] = (uint8_t)nl;
    memcpy(b + n, m->name, nl);
    n += nl;
    b[n++] = m->ncand;
    for (uint8_t i = 0u; i < m->ncand; ++i) {
        size_t cl = put_ep_v2(b + n, sizeof(b) - n, &m->cand[i], false);
        if (cl == 0u) return 0u;
        n += cl;
    }
    if (m->has_license) {
        b[n++] = ASH_LICENSE_BYTES;
        memcpy(b + n, m->license, ASH_LICENSE_BYTES);
        n += ASH_LICENSE_BYTES;
    } else {
        b[n++] = 0u;
    }
    if (n > cap) return 0u;
    memcpy(out, b, n);
    return n;
}

bool ash_parse_lookup_v2(const uint8_t *buf, size_t len, ash_msg_lookup_v2_t *out) {
    const size_t fixed = 2u + 3u + 2u + 4u + ASH_COOKIE_LEN;
    if ((buf == NULL) || (out == NULL) || (len < (fixed + 3u))) return false;
    if ((buf[0] != ASH_SIG_MAGIC) || (buf[1] != (uint8_t)ASH_MSG_LOOKUP_V2)) return false;
    memset(out, 0, sizeof(*out));
    size_t o = 2u;
    out->flags      = buf[o++];
    out->client_nat = buf[o++];
    out->prefer_tcp = buf[o++];
    out->pool_id    = ash_get_be16(buf + o);
    o += 2u;
    out->req        = ash_get_be32(buf + o);
    o += 4u;
    memcpy(out->cookie, buf + o, ASH_COOKIE_LEN);
    o += ASH_COOKIE_LEN;

    uint8_t nl = buf[o++];
    if ((nl == 0u) || (nl > ASH_MAX_NAME_LEN) || ((o + nl + 1u) > len)) return false;
    memcpy(out->name, buf + o, nl);
    out->name[nl] = '\0';
    o += nl;

    uint8_t nc = buf[o++];
    if (nc > ASH_MAX_CANDS) return false;
    out->ncand = nc;
    for (uint8_t i = 0u; i < nc; ++i) {
        size_t cl = get_ep_v2(buf + o, len - o, &out->cand[i], false);
        if (cl == 0u) return false;
        o += cl;
    }
    if (o >= len) return false;
    uint8_t ll = buf[o++];
    if (ll == ASH_LICENSE_BYTES) {
        if ((o + ASH_LICENSE_BYTES) != len) return false;
        out->has_license = true;
        memcpy(out->license, buf + o, ASH_LICENSE_BYTES);
    } else if (ll == 0u) {
        if (o != len) return false;
    } else {
        return false;
    }
    return true;
}

size_t ash_build_conn_v2(uint8_t *out, size_t cap, const ash_msg_conn_v2_t *m) {
    if ((out == NULL) || (m == NULL)) return 0u;
    if ((m->type != (uint8_t)ASH_MSG_CONN_V2) && (m->type != (uint8_t)ASH_MSG_INCOMING_V2)) return 0u;
    if (m->ncand > ASH_MAX_CANDS) return 0u;

    uint8_t b[512];
    size_t n = 0u;
    b[n++] = ASH_SIG_MAGIC;
    b[n++] = m->type;
    ash_put_be32(b + n, m->req);
    n += 4u;
    ash_put_be32(b + n, m->sess);
    n += 4u;
    ash_put_be32(b + n, m->tok);
    n += 4u;
    b[n++] = m->punch_strategy;
    ash_put_be16(b + n, m->punch_sync_ms);
    n += 2u;
    ash_put_be16(b + n, (uint16_t)m->port_stride);
    n += 2u;
    b[n++] = m->peer_nat;
    b[n++] = m->host_flags;
    b[n++] = m->tier;
    ash_put_be32(b + n, m->relay_max_kbps);
    n += 4u;

    size_t ru = put_ep_v2(b + n, sizeof(b) - n, &m->relay_udp, true);
    if (ru == 0u) return 0u;
    n += ru;
    size_t rt = put_ep_v2(b + n, sizeof(b) - n, &m->relay_tcp, true);
    if (rt == 0u) return 0u;
    n += rt;

    memcpy(b + n, m->relay_ticket, ASH_TICKET_BYTES);
    n += ASH_TICKET_BYTES;

    b[n++] = m->ncand;
    for (uint8_t i = 0u; i < m->ncand; ++i) {
        size_t cl = put_ep_v2(b + n, sizeof(b) - n, &m->cand[i], false);
        if (cl == 0u) return 0u;
        n += cl;
    }
    if (n > cap) return 0u;
    memcpy(out, b, n);
    return n;
}

bool ash_parse_conn_v2(const uint8_t *buf, size_t len, ash_msg_conn_v2_t *out) {
    if ((buf == NULL) || (out == NULL) || (len < (26u + 2u + ASH_TICKET_BYTES + 1u))) return false;
    if (buf[0] != ASH_SIG_MAGIC) return false;
    if ((buf[1] != (uint8_t)ASH_MSG_CONN_V2) && (buf[1] != (uint8_t)ASH_MSG_INCOMING_V2)) return false;

    memset(out, 0, sizeof(*out));
    size_t o = 0u;
    out->type = buf[1];
    o = 2u;
    out->req            = ash_get_be32(buf + o); o += 4u;
    out->sess           = ash_get_be32(buf + o); o += 4u;
    out->tok            = ash_get_be32(buf + o); o += 4u;
    out->punch_strategy = buf[o++];
    out->punch_sync_ms  = ash_get_be16(buf + o); o += 2u;
    out->port_stride    = (int16_t)ash_get_be16(buf + o); o += 2u;
    out->peer_nat       = buf[o++];
    out->host_flags     = buf[o++];
    out->tier           = buf[o++];
    out->relay_max_kbps = ash_get_be32(buf + o); o += 4u;

    size_t ru = get_ep_v2(buf + o, len - o, &out->relay_udp, true);
    if (ru == 0u) return false;
    o += ru;
    size_t rt = get_ep_v2(buf + o, len - o, &out->relay_tcp, true);
    if (rt == 0u) return false;
    o += rt;

    if ((o + ASH_TICKET_BYTES + 1u) > len) return false;
    memcpy(out->relay_ticket, buf + o, ASH_TICKET_BYTES);
    o += ASH_TICKET_BYTES;

    uint8_t nc = buf[o++];
    if (nc > ASH_MAX_CANDS) return false;
    out->ncand = nc;
    for (uint8_t i = 0u; i < nc; ++i) {
        size_t cl = get_ep_v2(buf + o, len - o, &out->cand[i], false);
        if (cl == 0u) return false;
        o += cl;
    }
    return o == len;
}

static size_t build_unreg_transcript(const ash_msg_unreg_v2_t *m, uint8_t *out, size_t cap) {
    static const uint8_t k_dom[16] = {
        'A', 's', 'h', 'D', 'e', 's', 'k', '-', 'U', 'N', 'R', 'E', 'G', '-', 'v', '2'
    };
    size_t nl = strlen(m->name);
    if ((nl == 0u) || (nl > ASH_MAX_NAME_LEN) || ((16u + 8u + 1u + nl) > cap)) return 0u;
    memcpy(out, k_dom, sizeof(k_dom));
    ash_put_be64(out + 16u, m->ts_ms);
    out[24u] = (uint8_t)nl;
    for (size_t i = 0u; i < nl; ++i) {
        out[25u + i] = (uint8_t)m->name[i];
    }
    return 25u + nl;
}

void ash_unreg_v2_sign(ash_msg_unreg_v2_t *m, const uint8_t ed25519_secret[ASH_ED25519_SEC_LEN]) {
    if ((m == NULL) || (ed25519_secret == NULL)) return;
    memcpy(m->pubkey, ed25519_secret + 32u, ASH_ED25519_PUB_LEN);
    uint8_t tr[128];
    size_t tr_len = build_unreg_transcript(m, tr, sizeof(tr));
    if (tr_len == 0u) return;
    ash_ed25519_sign(ed25519_secret, tr, tr_len, m->sig);
}

bool ash_unreg_v2_verify_sig(const ash_msg_unreg_v2_t *m) {
    if (m == NULL) return false;
    uint8_t tr[128];
    size_t tr_len = build_unreg_transcript(m, tr, sizeof(tr));
    if (tr_len == 0u) return false;
    return ash_ed25519_verify(m->pubkey, tr, tr_len, m->sig);
}

size_t ash_build_unreg_v2(uint8_t *out, size_t cap, const ash_msg_unreg_v2_t *m) {
    if ((out == NULL) || (m == NULL)) return 0u;
    size_t nl = strlen(m->name);
    size_t need = 2u + 8u + ASH_ED25519_PUB_LEN + ASH_ED25519_SIG_LEN + 1u + nl;
    if ((nl == 0u) || (nl > ASH_MAX_NAME_LEN) || (cap < need)) return 0u;
    size_t n = 0u;
    out[n++] = ASH_SIG_MAGIC;
    out[n++] = (uint8_t)ASH_MSG_UNREG_V2;
    ash_put_be64(out + n, m->ts_ms); n += 8u;
    memcpy(out + n, m->pubkey, ASH_ED25519_PUB_LEN); n += ASH_ED25519_PUB_LEN;
    memcpy(out + n, m->sig, ASH_ED25519_SIG_LEN);    n += ASH_ED25519_SIG_LEN;
    out[n++] = (uint8_t)nl;
    memcpy(out + n, m->name, nl); n += nl;
    return n;
}

bool ash_parse_unreg_v2(const uint8_t *buf, size_t len, ash_msg_unreg_v2_t *out) {
    const size_t hdr = 2u + 8u + ASH_ED25519_PUB_LEN + ASH_ED25519_SIG_LEN + 1u;
    if ((buf == NULL) || (out == NULL) || (len <= hdr)) return false;
    if ((buf[0] != ASH_SIG_MAGIC) || (buf[1] != (uint8_t)ASH_MSG_UNREG_V2)) return false;
    memset(out, 0, sizeof(*out));
    out->ts_ms = ash_get_be64(buf + 2u);
    memcpy(out->pubkey, buf + 10u, ASH_ED25519_PUB_LEN);
    memcpy(out->sig, buf + 42u, ASH_ED25519_SIG_LEN);
    uint8_t nl = buf[106u];
    if ((nl == 0u) || (nl > ASH_MAX_NAME_LEN) || ((107u + nl) != len)) return false;
    memcpy(out->name, buf + 107u, nl);
    out->name[nl] = '\0';
    return true;
}

size_t ash_build_relay_bind(uint8_t *out, size_t cap, const ash_msg_relay_bind_t *m) {
    if ((out == NULL) || (m == NULL) || (cap < (3u + ASH_TICKET_BYTES))) return 0u;
    if ((m->role != 1u) && (m->role != 2u)) return 0u;
    out[0] = ASH_SIG_MAGIC;
    out[1] = (uint8_t)ASH_MSG_RELAY_BIND_V2;
    out[2] = m->role;
    memcpy(out + 3u, m->ticket, ASH_TICKET_BYTES);
    return 3u + ASH_TICKET_BYTES;
}

bool ash_parse_relay_bind(const uint8_t *buf, size_t len, ash_msg_relay_bind_t *out) {
    if ((buf == NULL) || (out == NULL) || (len != (3u + ASH_TICKET_BYTES))) return false;
    if ((buf[0] != ASH_SIG_MAGIC) || (buf[1] != (uint8_t)ASH_MSG_RELAY_BIND_V2)) return false;
    if ((buf[2] != 1u) && (buf[2] != 2u)) return false;
    out->role = buf[2];
    memcpy(out->ticket, buf + 3u, ASH_TICKET_BYTES);
    return true;
}

size_t ash_build_relay_bind_ok(uint8_t *out, size_t cap, const ash_msg_relay_bind_ok_t *m) {
    if ((out == NULL) || (m == NULL) || (cap < 15u)) return 0u;
    out[0] = ASH_SIG_MAGIC;
    out[1] = (uint8_t)ASH_MSG_RELAY_BIND_OK;
    out[2] = m->status;
    ash_put_be32(out + 3u, m->sess);
    ash_put_be32(out + 7u, m->tok);
    ash_put_be32(out + 11u, m->max_kbps);
    return 15u;
}

bool ash_parse_relay_bind_ok(const uint8_t *buf, size_t len, ash_msg_relay_bind_ok_t *out) {
    if ((buf == NULL) || (out == NULL) || (len != 15u)) return false;
    if ((buf[0] != ASH_SIG_MAGIC) || (buf[1] != (uint8_t)ASH_MSG_RELAY_BIND_OK)) return false;
    out->status   = buf[2];
    out->sess     = ash_get_be32(buf + 3u);
    out->tok      = ash_get_be32(buf + 7u);
    out->max_kbps = ash_get_be32(buf + 11u);
    return true;
}

size_t ash_build_node_hb(uint8_t *out, size_t cap,
                         const uint8_t cluster_secret[32],
                         const ash_msg_node_hb_t *m) {
    if ((out == NULL) || (cluster_secret == NULL) || (m == NULL)) return 0u;
    uint8_t b[160];
    size_t n = 0u;
    b[n++] = ASH_SIG_MAGIC;
    b[n++] = (uint8_t)ASH_MSG_NODE_HB;
    ash_put_be32(b + n, m->node_id); n += 4u;
    b[n++] = m->tier_max;
    ash_put_be16(b + n, m->pool_id); n += 2u;
    ash_put_be16(b + n, m->region_id); n += 2u;
    ash_put_be32(b + n, m->active_sessions); n += 4u;
    ash_put_be32(b + n, m->used_kbps); n += 4u;
    ash_put_be32(b + n, m->cap_kbps); n += 4u;
    ash_put_be64(b + n, m->ts_ms); n += 8u;

    size_t ulen = put_ep_v2(b + n, sizeof(b) - n - 32u, &m->public_udp, true);
    if (ulen == 0u) return 0u;
    n += ulen;
    size_t tlen = put_ep_v2(b + n, sizeof(b) - n - 32u, &m->public_tcp, true);
    if (tlen == 0u) return 0u;
    n += tlen;

    uint8_t mac[ASH_SHA256_BYTES];
    ash_hmac_sha256(cluster_secret, 32u, b, n, mac);
    memcpy(b + n, mac, 32u);
    n += 32u;
    ash_secure_zero(mac, sizeof(mac));

    if (n > cap) return 0u;
    memcpy(out, b, n);
    return n;
}

bool ash_parse_node_hb(const uint8_t *buf, size_t len,
                       const uint8_t cluster_secret[32],
                       ash_msg_node_hb_t *out) {
    if ((buf == NULL) || (cluster_secret == NULL) || (out == NULL) || (len < (31u + 2u + 32u))) {
        return false;
    }
    if ((buf[0] != ASH_SIG_MAGIC) || (buf[1] != (uint8_t)ASH_MSG_NODE_HB)) return false;

    size_t body_len = len - 32u;
    uint8_t mac[ASH_SHA256_BYTES];
    ash_hmac_sha256(cluster_secret, 32u, buf, body_len, mac);
    bool ok = ash_ct_equal(mac, buf + body_len, 32u);
    ash_secure_zero(mac, sizeof(mac));
    if (!ok) return false;

    memset(out, 0, sizeof(*out));
    size_t o = 2u;
    out->node_id         = ash_get_be32(buf + o); o += 4u;
    out->tier_max        = buf[o++];
    out->pool_id         = ash_get_be16(buf + o); o += 2u;
    out->region_id       = ash_get_be16(buf + o); o += 2u;
    out->active_sessions = ash_get_be32(buf + o); o += 4u;
    out->used_kbps       = ash_get_be32(buf + o); o += 4u;
    out->cap_kbps        = ash_get_be32(buf + o); o += 4u;
    out->ts_ms           = ash_get_be64(buf + o); o += 8u;

    size_t ulen = get_ep_v2(buf + o, body_len - o, &out->public_udp, true);
    if (ulen == 0u) return false;
    o += ulen;
    size_t tlen = get_ep_v2(buf + o, body_len - o, &out->public_tcp, true);
    if (tlen == 0u) return false;
    o += tlen;
    return o == body_len;
}

/* ---------------- TCP 443 Framing ---------------- */
size_t ash_tcp_frame_encode(ash_tcp_frame_mode_t mode,
                            const uint8_t *payload, size_t payload_len,
                            uint8_t *out, size_t cap) {
    if ((payload == NULL) || (out == NULL) || (payload_len == 0u) ||
        (payload_len > ASH_MAX_FRAME_PAYLOAD)) {
        return 0u;
    }
    if (mode == ASH_TCP_FRAME_TLS_APP) {
        if (cap < (5u + payload_len)) return 0u;
        out[0] = 0x17u; /* TLS ApplicationData */
        out[1] = 0x03u;
        out[2] = 0x03u; /* TLS 1.2 / 1.3 record version */
        ash_put_be16(out + 3u, (uint16_t)payload_len);
        memcpy(out + 5u, payload, payload_len);
        return 5u + payload_len;
    }
    if (cap < (2u + payload_len)) return 0u;
    ash_put_be16(out, (uint16_t)payload_len);
    memcpy(out + 2u, payload, payload_len);
    return 2u + payload_len;
}

int ash_tcp_frame_decode(ash_tcp_frame_mode_t *inout_mode,
                         const uint8_t *in, size_t in_len,
                         const uint8_t **out_payload, size_t *out_payload_len,
                         bool *out_need_http_101) {
    if ((inout_mode == NULL) || (in == NULL) || (out_payload == NULL) || (out_payload_len == NULL)) {
        return -1;
    }
    if (out_need_http_101 != NULL) *out_need_http_101 = false;
    if (in_len == 0u) return 0;

    if (*inout_mode == ASH_TCP_FRAME_UNKNOWN) {
        /* Auto-detect HTTP Upgrade / CONNECT preface vs TLS 0x17 record vs RFC 4571 */
        if ((in[0] == (uint8_t)'G') || (in[0] == (uint8_t)'C')) {
            if (in_len < 4u) return 0;
            /* Scan for "\r\n\r\n" up to 1024 bytes */
            size_t limit = (in_len < 1024u) ? in_len : 1024u;
            for (size_t i = 0u; (i + 3u) < limit; ++i) {
                if ((in[i] == '\r') && (in[i + 1u] == '\n') &&
                    (in[i + 2u] == '\r') && (in[i + 3u] == '\n')) {
                    *inout_mode       = ASH_TCP_FRAME_RFC4571;
                    *out_payload      = NULL;
                    *out_payload_len  = 0u;
                    if (out_need_http_101 != NULL) *out_need_http_101 = true;
                    return (int)(i + 4u);
                }
            }
            return (in_len >= 1024u) ? -1 : 0;
        }
        if (in[0] == 0x17u) {
            *inout_mode = ASH_TCP_FRAME_TLS_APP;
        } else {
            *inout_mode = ASH_TCP_FRAME_RFC4571;
        }
    }

    if (*inout_mode == ASH_TCP_FRAME_TLS_APP) {
        if (in_len < 5u) return 0;
        if ((in[0] != 0x17u) || (in[1] != 0x03u) || (in[2] != 0x03u)) return -1;
        uint16_t plen = ash_get_be16(in + 3u);
        if ((plen == 0u) || (plen > ASH_MAX_FRAME_PAYLOAD)) return -1;
        if (in_len < (5u + (size_t)plen)) return 0;
        *out_payload     = in + 5u;
        *out_payload_len = (size_t)plen;
        return (int)(5u + (size_t)plen);
    }

    if (in_len < 2u) return 0;
    uint16_t plen = ash_get_be16(in);
    if ((plen == 0u) || (plen > ASH_MAX_FRAME_PAYLOAD)) return -1;
    if (in_len < (2u + (size_t)plen)) return 0;
    *out_payload     = in + 2u;
    *out_payload_len = (size_t)plen;
    return (int)(2u + (size_t)plen);
}
