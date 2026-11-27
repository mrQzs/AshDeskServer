#ifndef ASH_CRYPTO_H
#define ASH_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ASH_SHA256_BYTES      32u
#define ASH_SHA512_BYTES      64u
#define ASH_ED25519_SEED_LEN  32u
#define ASH_ED25519_PUB_LEN   32u
#define ASH_ED25519_SEC_LEN   64u
#define ASH_ED25519_SIG_LEN   64u

/* Constant-time memory compare & compiler-barrier zeroing */
bool ash_ct_equal(const void *a, const void *b, size_t len);
void ash_secure_zero(void *p, size_t len);

/* Hex encoding/decoding utilities */
void ash_hex_encode(const uint8_t *in, size_t len, char *out);
bool ash_hex_decode(const char *hex, uint8_t *out, size_t out_len);

/* SipHash-2-4 (HashDoS-resistant 64-bit keyed PRF) */
uint64_t ash_siphash24(const uint8_t key[16], const void *data, size_t len);

/* SHA-256 & HMAC-SHA256 (RFC 6234 / RFC 2104) */
typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buf[64];
} ash_sha256_ctx;

void ash_sha256_init(ash_sha256_ctx *ctx);
void ash_sha256_update(ash_sha256_ctx *ctx, const void *data, size_t len);
void ash_sha256_final(ash_sha256_ctx *ctx, uint8_t out[ASH_SHA256_BYTES]);
void ash_sha256(const void *data, size_t len, uint8_t out[ASH_SHA256_BYTES]);

typedef struct {
    ash_sha256_ctx inner;
    ash_sha256_ctx outer;
} ash_hmac_sha256_ctx;

void ash_hmac_sha256_init(ash_hmac_sha256_ctx *ctx, const void *key, size_t key_len);
void ash_hmac_sha256_update(ash_hmac_sha256_ctx *ctx, const void *data, size_t len);
void ash_hmac_sha256_final(ash_hmac_sha256_ctx *ctx, uint8_t out[ASH_SHA256_BYTES]);
void ash_hmac_sha256(const void *key, size_t key_len,
                     const void *data, size_t len,
                     uint8_t out[ASH_SHA256_BYTES]);

/* SHA-512 (RFC 6234) */
typedef struct {
    uint64_t state[8];
    uint64_t count_lo;
    uint64_t count_hi;
    uint8_t  buf[128];
} ash_sha512_ctx;

void ash_sha512_init(ash_sha512_ctx *ctx);
void ash_sha512_update(ash_sha512_ctx *ctx, const void *data, size_t len);
void ash_sha512_final(ash_sha512_ctx *ctx, uint8_t out[ASH_SHA512_BYTES]);
void ash_sha512(const void *data, size_t len, uint8_t out[ASH_SHA512_BYTES]);

/* Ed25519 Digital Signatures (RFC 8032, canonical S < L & y < p enforced) */
void ash_ed25519_keypair(const uint8_t seed[ASH_ED25519_SEED_LEN],
                         uint8_t pub[ASH_ED25519_PUB_LEN],
                         uint8_t secret[ASH_ED25519_SEC_LEN]);

void ash_ed25519_sign(const uint8_t secret[ASH_ED25519_SEC_LEN],
                      const uint8_t *msg, size_t msg_len,
                      uint8_t sig[ASH_ED25519_SIG_LEN]);

bool ash_ed25519_verify(const uint8_t pub[ASH_ED25519_PUB_LEN],
                        const uint8_t *msg, size_t msg_len,
                        const uint8_t sig[ASH_ED25519_SIG_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* ASH_CRYPTO_H */
