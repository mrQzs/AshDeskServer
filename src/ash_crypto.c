#include "ash_crypto.h"
#include "ash_common.h"

#include <string.h>

bool ash_ct_equal(const void *a, const void *b, size_t len) {
    const volatile uint8_t *pa = (const volatile uint8_t *)a;
    const volatile uint8_t *pb = (const volatile uint8_t *)b;
    uint8_t diff = 0u;
    for (size_t i = 0u; i < len; ++i) {
        diff |= (uint8_t)(pa[i] ^ pb[i]);
    }
    return diff == 0u;
}

void ash_secure_zero(void *p, size_t len) {
    if (p == NULL) return;
    volatile uint8_t *vp = (volatile uint8_t *)p;
    for (size_t i = 0u; i < len; ++i) {
        vp[i] = 0u;
    }
}

void ash_hex_encode(const uint8_t *in, size_t len, char *out) {
    static const char k_hex[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };
    for (size_t i = 0u; i < len; ++i) {
        out[2u * i]        = k_hex[(in[i] >> 4u) & 0x0Fu];
        out[(2u * i) + 1u] = k_hex[in[i] & 0x0Fu];
    }
    out[2u * len] = '\0';
}

static int hex_nibble(char c) {
    uint8_t u = (uint8_t)c;
    if ((u >= (uint8_t)'0') && (u <= (uint8_t)'9')) return (int)(u - (uint8_t)'0');
    if ((u >= (uint8_t)'a') && (u <= (uint8_t)'f')) return (int)(u - (uint8_t)'a') + 10;
    if ((u >= (uint8_t)'A') && (u <= (uint8_t)'F')) return (int)(u - (uint8_t)'A') + 10;
    return -1;
}

bool ash_hex_decode(const char *hex, uint8_t *out, size_t out_len) {
    if ((hex == NULL) || ((out == NULL) && (out_len > 0u))) return false;
    if (strlen(hex) != (2u * out_len)) return false;
    for (size_t i = 0u; i < out_len; ++i) {
        int hi = hex_nibble(hex[2u * i]);
        int lo = hex_nibble(hex[(2u * i) + 1u]);
        if ((hi < 0) || (lo < 0)) return false;
        out[i] = (uint8_t)(((uint32_t)hi << 4u) | (uint32_t)lo);
    }
    return true;
}

/* ---------------- SipHash-2-4 ---------------- */
static inline uint64_t rotl64(uint64_t x, unsigned b) {
    return (x << b) | (x >> (64u - b));
}

#define SIPROUND()           \
    do {                     \
        v0 += v1;            \
        v1 = rotl64(v1, 13); \
        v1 ^= v0;            \
        v0 = rotl64(v0, 32); \
        v2 += v3;            \
        v3 = rotl64(v3, 16); \
        v3 ^= v2;            \
        v0 += v3;            \
        v3 = rotl64(v3, 21); \
        v3 ^= v0;            \
        v2 += v1;            \
        v1 = rotl64(v1, 17); \
        v1 ^= v2;            \
        v2 = rotl64(v2, 32); \
    } while (0)

uint64_t ash_siphash24(const uint8_t key[16], const void *data, size_t len) {
    uint64_t k0 = ash_get_le64(key);
    uint64_t k1 = ash_get_le64(key + 8);
    uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
    uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
    uint64_t v3 = 0x7465646279746573ULL ^ k1;

    const uint8_t *in  = (const uint8_t *)data;
    const uint8_t *end = in + (len - (len % 8u));
    uint64_t b = ((uint64_t)len) << 56u;

    for (; in != end; in += 8) {
        uint64_t m = ash_get_le64(in);
        v3 ^= m;
        SIPROUND();
        SIPROUND();
        v0 ^= m;
    }

    switch (len & 7u) {
    case 7u: b |= ((uint64_t)in[6]) << 48u; /* FALLTHROUGH */
    case 6u: b |= ((uint64_t)in[5]) << 40u; /* FALLTHROUGH */
    case 5u: b |= ((uint64_t)in[4]) << 32u; /* FALLTHROUGH */
    case 4u: b |= ((uint64_t)in[3]) << 24u; /* FALLTHROUGH */
    case 3u: b |= ((uint64_t)in[2]) << 16u; /* FALLTHROUGH */
    case 2u: b |= ((uint64_t)in[1]) << 8u;  /* FALLTHROUGH */
    case 1u: b |= ((uint64_t)in[0]); break;
    case 0u: default: break;
    }

    v3 ^= b;
    SIPROUND();
    SIPROUND();
    v0 ^= b;
    v2 ^= 0xffULL;
    SIPROUND();
    SIPROUND();
    SIPROUND();
    SIPROUND();
    return v0 ^ v1 ^ v2 ^ v3;
}

/* ---------------- SHA-256 & HMAC-SHA256 ---------------- */
static inline uint32_t rotr32(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32u - n));
}

static const uint32_t k_sha256[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static void sha256_block(uint32_t st[8], const uint8_t blk[64]) {
    uint32_t w[64];
    for (size_t i = 0u; i < 16u; ++i) {
        w[i] = ash_get_be32(blk + (4u * i));
    }
    for (size_t i = 16u; i < 64u; ++i) {
        uint32_t s0 = rotr32(w[i - 15u], 7u) ^ rotr32(w[i - 15u], 18u) ^ (w[i - 15u] >> 3u);
        uint32_t s1 = rotr32(w[i - 2u], 17u) ^ rotr32(w[i - 2u], 19u) ^ (w[i - 2u] >> 10u);
        w[i] = w[i - 16u] + s0 + w[i - 7u] + s1;
    }

    uint32_t a = st[0], b = st[1], c = st[2], d = st[3];
    uint32_t e = st[4], f = st[5], g = st[6], h = st[7];

    for (size_t i = 0u; i < 64u; ++i) {
        uint32_t S1  = rotr32(e, 6u) ^ rotr32(e, 11u) ^ rotr32(e, 25u);
        uint32_t ch  = (e & f) ^ ((~e) & g);
        uint32_t t1  = h + S1 + ch + k_sha256[i] + w[i];
        uint32_t S0  = rotr32(a, 2u) ^ rotr32(a, 13u) ^ rotr32(a, 22u);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2  = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    st[0] += a; st[1] += b; st[2] += c; st[3] += d;
    st[4] += e; st[5] += f; st[6] += g; st[7] += h;
}

void ash_sha256_init(ash_sha256_ctx *ctx) {
    ctx->state[0] = 0x6a09e667u;
    ctx->state[1] = 0xbb67ae85u;
    ctx->state[2] = 0x3c6ef372u;
    ctx->state[3] = 0xa54ff53au;
    ctx->state[4] = 0x510e527fu;
    ctx->state[5] = 0x9b05688cu;
    ctx->state[6] = 0x1f83d9abu;
    ctx->state[7] = 0x5be0cd19u;
    ctx->count    = 0ULL;
    memset(ctx->buf, 0, sizeof(ctx->buf));
}

void ash_sha256_update(ash_sha256_ctx *ctx, const void *data, size_t len) {
    if ((len == 0u) || (data == NULL)) return;
    const uint8_t *p = (const uint8_t *)data;
    size_t idx = (size_t)(ctx->count & 63ULL);
    ctx->count += (uint64_t)len;

    if (idx > 0u) {
        size_t need = 64u - idx;
        if (len < need) {
            memcpy(ctx->buf + idx, p, len);
            return;
        }
        memcpy(ctx->buf + idx, p, need);
        sha256_block(ctx->state, ctx->buf);
        p   += need;
        len -= need;
    }
    while (len >= 64u) {
        sha256_block(ctx->state, p);
        p   += 64u;
        len -= 64u;
    }
    if (len > 0u) {
        memcpy(ctx->buf, p, len);
    }
}

void ash_sha256_final(ash_sha256_ctx *ctx, uint8_t out[ASH_SHA256_BYTES]) {
    uint64_t bits = ctx->count * 8ULL;
    size_t idx = (size_t)(ctx->count & 63ULL);
    ctx->buf[idx++] = 0x80u;
    if (idx > 56u) {
        memset(ctx->buf + idx, 0, 64u - idx);
        sha256_block(ctx->state, ctx->buf);
        idx = 0u;
    }
    memset(ctx->buf + idx, 0, 56u - idx);
    ash_put_be64(ctx->buf + 56u, bits);
    sha256_block(ctx->state, ctx->buf);
    for (size_t i = 0u; i < 8u; ++i) {
        ash_put_be32(out + (4u * i), ctx->state[i]);
    }
    ash_secure_zero(ctx, sizeof(*ctx));
}

void ash_sha256(const void *data, size_t len, uint8_t out[ASH_SHA256_BYTES]) {
    ash_sha256_ctx ctx;
    ash_sha256_init(&ctx);
    ash_sha256_update(&ctx, data, len);
    ash_sha256_final(&ctx, out);
}

void ash_hmac_sha256_init(ash_hmac_sha256_ctx *ctx, const void *key, size_t key_len) {
    uint8_t k_pad[64];
    memset(k_pad, 0, sizeof(k_pad));
    if (key_len > 64u) {
        ash_sha256(key, key_len, k_pad);
    } else if ((key != NULL) && (key_len > 0u)) {
        memcpy(k_pad, key, key_len);
    }

    uint8_t block[64];
    for (size_t i = 0u; i < 64u; ++i) block[i] = (uint8_t)(k_pad[i] ^ 0x36u);
    ash_sha256_init(&ctx->inner);
    ash_sha256_update(&ctx->inner, block, 64u);

    for (size_t i = 0u; i < 64u; ++i) block[i] = (uint8_t)(k_pad[i] ^ 0x5cu);
    ash_sha256_init(&ctx->outer);
    ash_sha256_update(&ctx->outer, block, 64u);

    ash_secure_zero(k_pad, sizeof(k_pad));
    ash_secure_zero(block, sizeof(block));
}

void ash_hmac_sha256_update(ash_hmac_sha256_ctx *ctx, const void *data, size_t len) {
    ash_sha256_update(&ctx->inner, data, len);
}

void ash_hmac_sha256_final(ash_hmac_sha256_ctx *ctx, uint8_t out[ASH_SHA256_BYTES]) {
    uint8_t inner_hash[ASH_SHA256_BYTES];
    ash_sha256_final(&ctx->inner, inner_hash);
    ash_sha256_update(&ctx->outer, inner_hash, sizeof(inner_hash));
    ash_sha256_final(&ctx->outer, out);
    ash_secure_zero(inner_hash, sizeof(inner_hash));
}

void ash_hmac_sha256(const void *key, size_t key_len,
                     const void *data, size_t len,
                     uint8_t out[ASH_SHA256_BYTES]) {
    ash_hmac_sha256_ctx ctx;
    ash_hmac_sha256_init(&ctx, key, key_len);
    ash_hmac_sha256_update(&ctx, data, len);
    ash_hmac_sha256_final(&ctx, out);
}

/* ---------------- SHA-512 ---------------- */
static inline uint64_t rotr64(uint64_t x, unsigned n) {
    return (x >> n) | (x << (64u - n));
}

static const uint64_t k_sha512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

static void sha512_block(uint64_t st[8], const uint8_t blk[128]) {
    uint64_t w[80];
    for (size_t i = 0u; i < 16u; ++i) {
        w[i] = ash_get_be64(blk + (8u * i));
    }
    for (size_t i = 16u; i < 80u; ++i) {
        uint64_t s0 = rotr64(w[i - 15u], 1u) ^ rotr64(w[i - 15u], 8u) ^ (w[i - 15u] >> 7u);
        uint64_t s1 = rotr64(w[i - 2u], 19u) ^ rotr64(w[i - 2u], 61u) ^ (w[i - 2u] >> 6u);
        w[i] = w[i - 16u] + s0 + w[i - 7u] + s1;
    }

    uint64_t a = st[0], b = st[1], c = st[2], d = st[3];
    uint64_t e = st[4], f = st[5], g = st[6], h = st[7];

    for (size_t i = 0u; i < 80u; ++i) {
        uint64_t S1  = rotr64(e, 14u) ^ rotr64(e, 18u) ^ rotr64(e, 41u);
        uint64_t ch  = (e & f) ^ ((~e) & g);
        uint64_t t1  = h + S1 + ch + k_sha512[i] + w[i];
        uint64_t S0  = rotr64(a, 28u) ^ rotr64(a, 34u) ^ rotr64(a, 39u);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint64_t t2  = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    st[0] += a; st[1] += b; st[2] += c; st[3] += d;
    st[4] += e; st[5] += f; st[6] += g; st[7] += h;
}

void ash_sha512_init(ash_sha512_ctx *ctx) {
    ctx->state[0] = 0x6a09e667f3bcc908ULL;
    ctx->state[1] = 0xbb67ae8584caa73bULL;
    ctx->state[2] = 0x3c6ef372fe94f82bULL;
    ctx->state[3] = 0xa54ff53a5f1d36f1ULL;
    ctx->state[4] = 0x510e527fade682d1ULL;
    ctx->state[5] = 0x9b05688c2b3e6c1fULL;
    ctx->state[6] = 0x1f83d9abfb41bd6bULL;
    ctx->state[7] = 0x5be0cd19137e2179ULL;
    ctx->count_lo = 0ULL;
    ctx->count_hi = 0ULL;
    memset(ctx->buf, 0, sizeof(ctx->buf));
}

void ash_sha512_update(ash_sha512_ctx *ctx, const void *data, size_t len) {
    if ((len == 0u) || (data == NULL)) return;
    const uint8_t *p = (const uint8_t *)data;
    size_t idx = (size_t)(ctx->count_lo & 127ULL);
    uint64_t add = (uint64_t)len;
    ctx->count_lo += add;
    if (ctx->count_lo < add) {
        ctx->count_hi += 1ULL;
    }

    if (idx > 0u) {
        size_t need = 128u - idx;
        if (len < need) {
            memcpy(ctx->buf + idx, p, len);
            return;
        }
        memcpy(ctx->buf + idx, p, need);
        sha512_block(ctx->state, ctx->buf);
        p   += need;
        len -= need;
    }
    while (len >= 128u) {
        sha512_block(ctx->state, p);
        p   += 128u;
        len -= 128u;
    }
    if (len > 0u) {
        memcpy(ctx->buf, p, len);
    }
}

void ash_sha512_final(ash_sha512_ctx *ctx, uint8_t out[ASH_SHA512_BYTES]) {
    uint64_t bits_hi = (ctx->count_hi << 3u) | (ctx->count_lo >> 61u);
    uint64_t bits_lo = ctx->count_lo << 3u;
    size_t idx = (size_t)(ctx->count_lo & 127ULL);
    ctx->buf[idx++] = 0x80u;
    if (idx > 112u) {
        memset(ctx->buf + idx, 0, 128u - idx);
        sha512_block(ctx->state, ctx->buf);
        idx = 0u;
    }
    memset(ctx->buf + idx, 0, 112u - idx);
    ash_put_be64(ctx->buf + 112u, bits_hi);
    ash_put_be64(ctx->buf + 120u, bits_lo);
    sha512_block(ctx->state, ctx->buf);
    for (size_t i = 0u; i < 8u; ++i) {
        ash_put_be64(out + (8u * i), ctx->state[i]);
    }
    ash_secure_zero(ctx, sizeof(*ctx));
}

void ash_sha512(const void *data, size_t len, uint8_t out[ASH_SHA512_BYTES]) {
    ash_sha512_ctx ctx;
    ash_sha512_init(&ctx);
    ash_sha512_update(&ctx, data, len);
    ash_sha512_final(&ctx, out);
}

/* ---------------- RFC 8032 Ed25519 ----------------
 * Portable 16-limb GF(2^255-19) arithmetic (UB-free floor division, constant-time scalar ladder,
 * strict RFC 8032 canonical scalar S < L and canonical field encoding y < p verification). */
typedef int64_t fe25519[16];

static const fe25519 k_fe_0 = { 0 };
static const fe25519 k_fe_1 = { 1 };
/* d = -121665 / 121666 mod p */
static const fe25519 k_fe_d = {
    0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
    0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203
};
/* 2 * d mod p */
static const fe25519 k_fe_d2 = {
    0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
    0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406
};
/* sqrt(-1) mod p */
static const fe25519 k_fe_I = {
    0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
    0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83
};
/* Base point X and Y coordinates */
static const fe25519 k_bx = {
    0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
    0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169
};
static const fe25519 k_by = {
    0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
    0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666
};

/* Group order L = 2^252 + 27742317777372353535851937790883648493 */
static const uint8_t k_ed25519_L[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

/* Prime p = 2^255 - 19 */
static const uint8_t k_ed25519_P[32] = {
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
};

/* Branchless, UB-free floor(v / 2^k) for |v| < 2^45 (allows full SIMD auto-vectorization) */
static inline int64_t sar16(int64_t v) {
    const int64_t bias = ((int64_t)1) << 46;
    uint64_t u = (uint64_t)(v + bias);
    return (int64_t)(u >> 16u) - (((int64_t)1) << 30);
}

static inline int64_t sar8(int64_t v) {
    const int64_t bias = ((int64_t)1) << 46;
    uint64_t u = (uint64_t)(v + bias);
    return (int64_t)(u >> 8u) - (((int64_t)1) << 38);
}

static inline int64_t sar4(int64_t v) {
    const int64_t bias = ((int64_t)1) << 46;
    uint64_t u = (uint64_t)(v + bias);
    return (int64_t)(u >> 4u) - (((int64_t)1) << 42);
}

static void fe_copy(fe25519 o, const fe25519 a) {
    memcpy(o, a, sizeof(fe25519));
}

static void fe_cswap(fe25519 p, fe25519 q, int b) {
    uint64_t mask = (b != 0) ? UINT64_MAX : 0ULL;
    for (int i = 0; i < 16; ++i) {
        uint64_t pi = (uint64_t)p[i];
        uint64_t qi = (uint64_t)q[i];
        uint64_t t  = mask & (pi ^ qi);
        p[i] = (int64_t)(pi ^ t);
        q[i] = (int64_t)(qi ^ t);
    }
}

static void fe_carry(fe25519 o) {
    for (int i = 0; i < 15; ++i) {
        int64_t c = sar16(o[i]);
        o[i]     -= c * 65536;
        o[i + 1] += c;
    }
    int64_t c15 = sar16(o[15]);
    o[15] -= c15 * 65536;
    o[0]  += 38 * c15;

    int64_t c0 = sar16(o[0]);
    o[0] -= c0 * 65536;
    o[1] += c0;

    int64_t c1 = sar16(o[1]);
    o[1] -= c1 * 65536;
    o[2] += c1;
}

static void fe_add(fe25519 o, const fe25519 a, const fe25519 b) {
    for (int i = 0; i < 16; ++i) o[i] = a[i] + b[i];
}

static void fe_sub(fe25519 o, const fe25519 a, const fe25519 b) {
    for (int i = 0; i < 16; ++i) o[i] = a[i] - b[i];
}

static void fe_mul(fe25519 o, const fe25519 a, const fe25519 b) {
    int64_t t[31];
    memset(t, 0, sizeof(t));
    for (int i = 0; i < 16; ++i) {
        int64_t ai = a[i];
        for (int j = 0; j < 16; ++j) {
            t[i + j] += ai * b[j];
        }
    }
    for (int i = 0; i < 15; ++i) {
        t[i] += 38 * t[i + 16];
    }
    for (int i = 0; i < 16; ++i) o[i] = t[i];
    fe_carry(o);
}

static void fe_sq(fe25519 o, const fe25519 a) {
    int64_t t[31];
    memset(t, 0, sizeof(t));
    for (size_t i = 0u; i < 16u; ++i) {
        int64_t ai  = a[i];
        int64_t ai2 = ai * 2;
        t[2u * i] += ai * ai;
        for (size_t j = i + 1u; j < 16u; ++j) {
            t[i + j] += ai2 * a[j];
        }
    }
    for (size_t i = 0u; i < 15u; ++i) {
        t[i] += 38 * t[i + 16u];
    }
    for (size_t i = 0u; i < 16u; ++i) o[i] = t[i];
    fe_carry(o);
}

static void fe_inv(fe25519 o, const fe25519 inp) {
    fe25519 c;
    fe_copy(c, inp);
    for (int a = 253; a >= 0; --a) {
        fe_sq(c, c);
        if ((a != 2) && (a != 4)) {
            fe_mul(c, c, inp);
        }
    }
    fe_copy(o, c);
}

static void fe_pow2523(fe25519 o, const fe25519 inp) {
    fe25519 c;
    fe_copy(c, inp);
    for (int a = 250; a >= 0; --a) {
        fe_sq(c, c);
        if (a != 1) {
            fe_mul(c, c, inp);
        }
    }
    fe_copy(o, c);
}

static void fe_pack(uint8_t o[32], const fe25519 n) {
    fe25519 m, t;
    fe_copy(t, n);
    fe_carry(t);
    fe_carry(t);
    fe_carry(t);
    for (int j = 0; j < 2; ++j) {
        m[0] = t[0] - 0xffed;
        for (int i = 1; i < 15; ++i) {
            int64_t b = (m[i - 1] < 0) ? 1 : 0;
            m[i] = t[i] - 0xffff - b;
            m[i - 1] = (int64_t)((uint64_t)(m[i - 1] + (b * 65536)) & 0xFFFFu);
        }
        int64_t b14 = (m[14] < 0) ? 1 : 0;
        m[15] = t[15] - 0x7fff - b14;
        m[14] = (int64_t)((uint64_t)(m[14] + (b14 * 65536)) & 0xFFFFu);
        int swap_no = (m[15] < 0) ? 1 : 0;
        m[15] = (int64_t)((uint64_t)(m[15] + ((int64_t)swap_no * 65536)) & 0xFFFFu);
        fe_cswap(t, m, 1 - swap_no);
    }
    for (size_t i = 0u; i < 16u; ++i) {
        o[2u * i]       = (uint8_t)((uint64_t)t[i] & 0xFFu);
        o[(2u * i) + 1u] = (uint8_t)(((uint64_t)t[i] >> 8u) & 0xFFu);
    }
}

static void fe_unpack(fe25519 o, const uint8_t n[32]) {
    for (size_t i = 0u; i < 16u; ++i) {
        o[i] = (int64_t)n[2u * i] + (((int64_t)n[(2u * i) + 1u]) << 8u);
    }
    o[15] &= 0x7fff;
}

static uint8_t fe_parity(const fe25519 a) {
    uint8_t d[32];
    fe_pack(d, a);
    return (uint8_t)(d[0] & 1u);
}

static bool fe_eq(const fe25519 a, const fe25519 b) {
    uint8_t da[32], db[32];
    fe_pack(da, a);
    fe_pack(db, b);
    return ash_ct_equal(da, db, 32u);
}

typedef struct {
    fe25519 X, Y, Z, T;
} ge_pt;

static void ge_cswap(ge_pt *p, ge_pt *q, int b) {
    fe_cswap(p->X, q->X, b);
    fe_cswap(p->Y, q->Y, b);
    fe_cswap(p->Z, q->Z, b);
    fe_cswap(p->T, q->T, b);
}

static void ge_add(ge_pt *p, const ge_pt *q) {
    fe25519 a, b, c, d, e, f, g, h, t;
    fe_sub(a, p->Y, p->X);
    fe_sub(t, q->Y, q->X);
    fe_mul(a, a, t);
    fe_add(b, p->Y, p->X);
    fe_add(t, q->Y, q->X);
    fe_mul(b, b, t);
    fe_mul(c, p->T, q->T);
    fe_mul(c, c, k_fe_d2);
    fe_mul(d, p->Z, q->Z);
    fe_add(d, d, d);
    fe_sub(e, b, a);
    fe_sub(f, d, c);
    fe_add(g, d, c);
    fe_add(h, b, a);
    fe_mul(p->X, e, f);
    fe_mul(p->Y, h, g);
    fe_mul(p->Z, g, f);
    fe_mul(p->T, e, h);
}

static void ge_scalarmult(ge_pt *p, const ge_pt *q, const uint8_t s[32]) {
    fe_copy(p->X, k_fe_0);
    fe_copy(p->Y, k_fe_1);
    fe_copy(p->Z, k_fe_1);
    fe_copy(p->T, k_fe_0);
    ge_pt cur = *q;
    for (int i = 255; i >= 0; --i) {
        int b = (int)(((uint32_t)s[i / 8] >> ((unsigned)i & 7u)) & 1u);
        ge_cswap(p, &cur, b);
        ge_add(&cur, p);
        ge_add(p, p);
        ge_cswap(p, &cur, b);
    }
}

static void ge_scalarmult_base(ge_pt *p, const uint8_t s[32]) {
    ge_pt base;
    fe_copy(base.X, k_bx);
    fe_copy(base.Y, k_by);
    fe_copy(base.Z, k_fe_1);
    fe_mul(base.T, k_bx, k_by);
    ge_scalarmult(p, &base, s);
}

static void ge_pack(uint8_t r[32], const ge_pt *p) {
    fe25519 tx, ty, zi;
    fe_inv(zi, p->Z);
    fe_mul(tx, p->X, zi);
    fe_mul(ty, p->Y, zi);
    fe_pack(r, ty);
    r[31] ^= (uint8_t)(fe_parity(tx) << 7u);
}

static bool bytes_lt_32_le(const uint8_t a[32], const uint8_t bound[32]) {
    for (int i = 31; i >= 0; --i) {
        if (a[i] < bound[i]) return true;
        if (a[i] > bound[i]) return false;
    }
    return false;
}

static bool ge_unpack_neg(ge_pt *r, const uint8_t p[32]) {
    uint8_t y_bytes[32];
    memcpy(y_bytes, p, 32u);
    y_bytes[31] &= 0x7Fu;
    if (!bytes_lt_32_le(y_bytes, k_ed25519_P)) {
        return false; /* Reject non-canonical y >= 2^255 - 19 (RFC 8032 §5.1.3) */
    }

    fe25519 num, den, den2, den4, den6, chk;
    fe_unpack(r->Y, p);
    fe_copy(r->Z, k_fe_1);
    fe_sq(num, r->Y);
    fe_mul(den, num, k_fe_d);
    fe_sub(num, num, r->Z);       /* num = y^2 - 1 */
    fe_add(den, den, r->Z);       /* den = d * y^2 + 1 */

    fe_sq(den2, den);
    fe_sq(den4, den2);
    fe_mul(den6, den4, den2);
    fe_mul(r->X, den6, num);
    fe_mul(r->X, r->X, den);
    fe_pow2523(r->X, r->X);
    fe_mul(r->X, r->X, num);
    fe_mul(r->X, r->X, den2);
    fe_mul(r->X, r->X, den);

    fe_sq(chk, r->X);
    fe_mul(chk, chk, den);
    if (!fe_eq(chk, num)) {
        fe_mul(r->X, r->X, k_fe_I);
        fe_sq(chk, r->X);
        fe_mul(chk, chk, den);
        if (!fe_eq(chk, num)) {
            return false;
        }
    }

    uint8_t sign_bit = (uint8_t)((p[31] >> 7u) & 1u);
    if (fe_parity(r->X) == 0u && sign_bit == 1u) {
        /* x == 0 with sign bit 1 is invalid per RFC 8032 §5.1.3 */
        if (fe_eq(r->X, k_fe_0)) return false;
    }
    if (fe_parity(r->X) != sign_bit) {
        fe_sub(r->X, k_fe_0, r->X);
    }
    /* Negate X so r represents -A (for [S]B + [k](-A) == R check) */
    fe_sub(r->X, k_fe_0, r->X);
    fe_mul(r->T, r->X, r->Y);
    return true;
}

static void sc_mod_L(uint8_t r[32], int64_t x[64]) {
    for (int i = 63; i >= 32; --i) {
        int64_t carry = 0;
        int j;
        int k = i - 12;
        for (j = i - 32; j < k; ++j) {
            x[j] += carry - (16 * x[i] * (int64_t)k_ed25519_L[j - (i - 32)]);
            carry = sar8(x[j]);
            x[j] -= carry * 256;
        }
        x[j] += carry;
        x[i] = 0;
    }
    int64_t carry = 0;
    for (int j = 0; j < 32; ++j) {
        x[j] += carry - (sar4(x[31]) * (int64_t)k_ed25519_L[j]);
        carry = sar8(x[j]);
        x[j] -= carry * 256;
    }
    for (int j = 0; j < 32; ++j) {
        x[j] -= carry * (int64_t)k_ed25519_L[j];
    }
    for (int i = 0; i < 32; ++i) {
        x[i + 1] += sar8(x[i]);
        r[i] = (uint8_t)((uint64_t)x[i] & 0xFFu);
    }
}

void ash_ed25519_keypair(const uint8_t seed[ASH_ED25519_SEED_LEN],
                         uint8_t pub[ASH_ED25519_PUB_LEN],
                         uint8_t secret[ASH_ED25519_SEC_LEN]) {
    uint8_t d[64];
    ash_sha512(seed, ASH_ED25519_SEED_LEN, d);
    d[0]  &= 248u;
    d[31] &= 127u;
    d[31] |= 64u;

    ge_pt A;
    ge_scalarmult_base(&A, d);
    ge_pack(pub, &A);

    memcpy(secret, seed, 32u);
    memcpy(secret + 32u, pub, 32u);
    ash_secure_zero(d, sizeof(d));
}

void ash_ed25519_sign(const uint8_t secret[ASH_ED25519_SEC_LEN],
                      const uint8_t *msg, size_t msg_len,
                      uint8_t sig[ASH_ED25519_SIG_LEN]) {
    uint8_t d[64], r_hash[64], hram[64], r_sc[32];
    int64_t x[64];

    ash_sha512(secret, 32u, d);
    d[0]  &= 248u;
    d[31] &= 127u;
    d[31] |= 64u;

    ash_sha512_ctx ctx;
    ash_sha512_init(&ctx);
    ash_sha512_update(&ctx, d + 32u, 32u);
    ash_sha512_update(&ctx, msg, msg_len);
    ash_sha512_final(&ctx, r_hash);

    for (int i = 0; i < 64; ++i) x[i] = (int64_t)r_hash[i];
    sc_mod_L(r_sc, x);

    ge_pt R;
    ge_scalarmult_base(&R, r_sc);
    ge_pack(sig, &R);

    ash_sha512_init(&ctx);
    ash_sha512_update(&ctx, sig, 32u);
    ash_sha512_update(&ctx, secret + 32u, 32u);
    ash_sha512_update(&ctx, msg, msg_len);
    ash_sha512_final(&ctx, hram);

    uint8_t k_sc[32];
    for (int i = 0; i < 64; ++i) x[i] = (int64_t)hram[i];
    sc_mod_L(k_sc, x);

    for (int i = 0; i < 64; ++i) x[i] = 0;
    for (int i = 0; i < 32; ++i) x[i] = (int64_t)r_sc[i];
    for (int i = 0; i < 32; ++i) {
        for (int j = 0; j < 32; ++j) {
            x[i + j] += (int64_t)k_sc[i] * (int64_t)d[j];
        }
    }
    sc_mod_L(sig + 32u, x);

    ash_secure_zero(d, sizeof(d));
    ash_secure_zero(r_hash, sizeof(r_hash));
    ash_secure_zero(r_sc, sizeof(r_sc));
    ash_secure_zero(x, sizeof(x));
}

bool ash_ed25519_verify(const uint8_t pub[ASH_ED25519_PUB_LEN],
                        const uint8_t *msg, size_t msg_len,
                        const uint8_t sig[ASH_ED25519_SIG_LEN]) {
    if ((pub == NULL) || (sig == NULL)) return false;
    if ((msg == NULL) && (msg_len > 0u)) return false;

    /* Strict RFC 8032 §5.1.7 non-malleability check: S < L */
    if (!bytes_lt_32_le(sig + 32u, k_ed25519_L)) {
        return false;
    }

    ge_pt neg_A;
    if (!ge_unpack_neg(&neg_A, pub)) {
        return false;
    }

    uint8_t hram[64], k_sc[32];
    ash_sha512_ctx ctx;
    ash_sha512_init(&ctx);
    ash_sha512_update(&ctx, sig, 32u);
    ash_sha512_update(&ctx, pub, 32u);
    ash_sha512_update(&ctx, msg, msg_len);
    ash_sha512_final(&ctx, hram);

    int64_t x[64];
    for (int i = 0; i < 64; ++i) x[i] = (int64_t)hram[i];
    sc_mod_L(k_sc, x);

    /* Public verification Shamir's 2-bit simultaneous double-scalar multiplication:
     * computes [S]B + [k](-A) in 128 window steps instead of 2 x 256 ladder steps. */
    ge_pt B_pt;
    memset(&B_pt, 0, sizeof(B_pt));
    fe_copy(B_pt.X, k_bx);
    fe_copy(B_pt.Y, k_by);
    fe_copy(B_pt.Z, k_fe_1);
    fe_mul(B_pt.T, k_bx, k_by);

    ge_pt b_mul[4], a_mul[4];
    fe_copy(b_mul[0].X, k_fe_0); fe_copy(b_mul[0].Y, k_fe_1);
    fe_copy(b_mul[0].Z, k_fe_1); fe_copy(b_mul[0].T, k_fe_0);
    b_mul[1] = B_pt;
    b_mul[2] = B_pt; ge_add(&b_mul[2], &B_pt);
    b_mul[3] = b_mul[2]; ge_add(&b_mul[3], &B_pt);

    a_mul[0] = b_mul[0];
    a_mul[1] = neg_A;
    a_mul[2] = neg_A; ge_add(&a_mul[2], &neg_A);
    a_mul[3] = a_mul[2]; ge_add(&a_mul[3], &neg_A);

    ge_pt acc = b_mul[0];
    const uint8_t *s_sc = sig + 32u;
    for (int w = 127; w >= 0; --w) {
        ge_add(&acc, &acc);
        ge_add(&acc, &acc);
        unsigned bit_pos = (unsigned)(w * 2);
        unsigned sb = ((uint32_t)s_sc[bit_pos / 8u] >> (bit_pos & 7u)) & 3u;
        unsigned kb = ((uint32_t)k_sc[bit_pos / 8u] >> (bit_pos & 7u)) & 3u;
        if (sb != 0u) ge_add(&acc, &b_mul[sb]);
        if (kb != 0u) ge_add(&acc, &a_mul[kb]);
    }

    uint8_t check_R[32];
    ge_pack(check_R, &acc);
    return ash_ct_equal(check_R, sig, 32u);
}
