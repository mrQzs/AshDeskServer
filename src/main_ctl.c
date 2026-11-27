#include "ash_common.h"
#include "ash_crypto.h"
#include "ash_wire.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#endif

static void usage(void) {
    fprintf(stderr,
        "用法:\n"
        "  ash_ctl gen-secret\n"
        "  ash_ctl gen-devkey\n"
        "  ash_ctl issue-license --secret <64位HEX> --tier free|pro|vip|dedicated "
        "[--kbps N] [--pool-id N] [--days N] [--device 名称]\n"
        "  ash_ctl verify-license --secret <64位HEX> --token <80位HEX> [--device 名称]\n"
    );
}

static bool parse_u32(const char *s, uint32_t *out) {
    if ((s == NULL) || (*s == '\0')) return false;
    uint64_t v = 0ULL;
    for (size_t i = 0u; s[i] != '\0'; ++i) {
        if ((s[i] < '0') || (s[i] > '9')) return false;
        v = (v * 10ULL) + (uint64_t)((uint32_t)(uint8_t)s[i] - (uint32_t)'0');
        if (v > 0xFFFFFFFFULL) return false;
    }
    *out = (uint32_t)v;
    return true;
}

static int cmd_gen_secret(void) {
    uint8_t raw[32];
    if (!ash_csprng(raw, sizeof(raw))) return 1;
    char hex[65];
    ash_hex_encode(raw, sizeof(raw), hex);
    ash_secure_zero(raw, sizeof(raw));
    printf("%s\n", hex);
    return 0;
}

static int cmd_gen_devkey(void) {
    uint8_t seed[32], pub[32], sec[64];
    if (!ash_csprng(seed, sizeof(seed))) return 1;
    ash_ed25519_keypair(seed, pub, sec);
    char seed_hex[65], pub_hex[65], sec_hex[129];
    ash_hex_encode(seed, 32u, seed_hex);
    ash_hex_encode(pub, 32u, pub_hex);
    ash_hex_encode(sec, 64u, sec_hex);
    ash_secure_zero(seed, sizeof(seed));
    ash_secure_zero(sec, sizeof(sec));
    printf("seed=%s\npubkey=%s\nsecret=%s\n", seed_hex, pub_hex, sec_hex);
    return 0;
}

static int cmd_issue_license(int argc, char **argv) {
    uint8_t secret[32];
    bool have_secret = false;
    ash_license_claims_t claims;
    memset(&claims, 0, sizeof(claims));
    uint32_t days = 0u;

    for (int i = 2; i < argc; ++i) {
        const char *a = argv[i];
        const char *v = ((i + 1) < argc) ? argv[++i] : NULL;
        if (v == NULL) return 2;

        uint32_t u = 0u;
        if (strcmp(a, "--secret") == 0) {
            if (!ash_hex_decode(v, secret, 32u)) return 2;
            have_secret = true;
        } else if (strcmp(a, "--tier") == 0) {
            if (strcmp(v, "free") == 0) claims.tier = (uint8_t)ASH_TIER_FREE;
            else if (strcmp(v, "pro") == 0) claims.tier = (uint8_t)ASH_TIER_PRO;
            else if (strcmp(v, "vip") == 0) claims.tier = (uint8_t)ASH_TIER_VIP;
            else if (strcmp(v, "dedicated") == 0) claims.tier = (uint8_t)ASH_TIER_DEDICATED;
            else return 2;
        } else if (strcmp(a, "--kbps") == 0) {
            if (!parse_u32(v, &claims.max_kbps)) return 2;
        } else if (strcmp(a, "--pool-id") == 0) {
            if (!parse_u32(v, &u) || (u > 65535u)) return 2;
            claims.pool_id = (uint16_t)u;
        } else if (strcmp(a, "--days") == 0) {
            if (!parse_u32(v, &days)) return 2;
        } else if (strcmp(a, "--device") == 0) {
            claims.subject_hash = ash_device_hash32(v);
        } else {
            return 2;
        }
    }

    if (!have_secret) return 2;
    if (days > 0u) {
        claims.expire_ms = ash_wall_ms() + ((uint64_t)days * 86400000ULL);
    }

    uint8_t raw[ASH_LICENSE_BYTES];
    ash_license_sign(secret, &claims, raw);
    ash_secure_zero(secret, sizeof(secret));

    char hex[(ASH_LICENSE_BYTES * 2u) + 1u];
    ash_hex_encode(raw, sizeof(raw), hex);
    printf("%s\n", hex);
    return 0;
}

static int cmd_verify_license(int argc, char **argv) {
    uint8_t secret[32], raw[ASH_LICENSE_BYTES];
    bool have_secret = false, have_token = false;
    const char *device = NULL;

    for (int i = 2; i < argc; ++i) {
        const char *a = argv[i];
        const char *v = ((i + 1) < argc) ? argv[++i] : NULL;
        if (v == NULL) return 2;

        if (strcmp(a, "--secret") == 0) {
            if (!ash_hex_decode(v, secret, 32u)) return 2;
            have_secret = true;
        } else if (strcmp(a, "--token") == 0) {
            if (!ash_hex_decode(v, raw, ASH_LICENSE_BYTES)) return 2;
            have_token = true;
        } else if (strcmp(a, "--device") == 0) {
            device = v;
        } else {
            return 2;
        }
    }
    if (!have_secret || !have_token) return 2;

    ash_license_claims_t claims;
    bool ok = ash_license_verify(secret, raw, device, ash_wall_ms(), &claims);
    ash_secure_zero(secret, sizeof(secret));
    if (!ok) {
        fprintf(stderr, "无效或已过期的授权 Token\n");
        return 1;
    }

    static const char *const k_tiers[4] = { "free", "pro", "vip", "dedicated" };
    printf("验证通过: tier=%s pool_id=%u max_kbps=%u expire_ms=%llu subject_hash=0x%08X\n",
           k_tiers[claims.tier & 3u],
           (unsigned)claims.pool_id,
           (unsigned)claims.max_kbps,
           (unsigned long long)claims.expire_ms,
           (unsigned)claims.subject_hash);
    return 0;
}

int main(int argc, char **argv) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    if (argc < 2) {
        usage();
        return 2;
    }
    if (strcmp(argv[1], "gen-secret") == 0)     return cmd_gen_secret();
    if (strcmp(argv[1], "gen-devkey") == 0)     return cmd_gen_devkey();
    if (strcmp(argv[1], "issue-license") == 0)  return cmd_issue_license(argc, argv);
    if (strcmp(argv[1], "verify-license") == 0) return cmd_verify_license(argc, argv);

    usage();
    return 2;
}
