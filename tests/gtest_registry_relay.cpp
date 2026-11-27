#include <gtest/gtest.h>

#include "ash_ratelimit.h"
#include "ash_registry.h"
#include "ash_relay.h"

#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

TEST(RegistryAndAuth, Ed25519PinningPreventsHijackAndPersistsKeystore) {
    const char *ks_file = "test_devices_pin.db";
    std::remove(ks_file);

    ash_registry_cfg_t cfg;
    std::memset(&cfg, 0, sizeof(cfg));
    cfg.allow_v1_unauth = true;
    cfg.host_ttl_us     = 60000000ULL;
    cfg.tier_kbps[0]    = 2000u;
    cfg.tier_kbps[1]    = 20000u;
    cfg.tier_kbps[2]    = 100000u;
    std::memset(cfg.license_secret, 0x5A, sizeof(cfg.license_secret));
    cfg.keystore_path   = ks_file;

    ash_registry_t reg;
    ASSERT_TRUE(ash_registry_init(&reg, 1024u, &cfg));

    uint8_t seed_a[32], pub_a[32], sec_a[64];
    uint8_t seed_b[32], pub_b[32], sec_b[64];
    std::memset(seed_a, 0xAA, 32u);
    std::memset(seed_b, 0xBB, 32u);
    ash_ed25519_keypair(seed_a, pub_a, sec_a);
    ash_ed25519_keypair(seed_b, pub_b, sec_b);

    ash_ep_t ep_a, ep_evil;
    ASSERT_TRUE(ash_ep_parse("203.0.113.10:44100", 0u, &ep_a));
    ASSERT_TRUE(ash_ep_parse("198.51.100.99:55000", 0u, &ep_evil));

    /* 1. Legitimate Host A claims "prod-render-node" via Ed25519 TOFU */
    ash_msg_reg_v2_t m_a;
    std::memset(&m_a, 0, sizeof(m_a));
    m_a.ts_ms = 1000ULL;
    std::strcpy(m_a.name, "prod-render-node");
    ash_reg_v2_sign(&m_a, sec_a);

    uint8_t tier = 99u;
    EXPECT_EQ(ash_registry_on_reg_v2(&reg, &m_a, &ep_a, 0ULL, 1000000ULL, 1000ULL, &tier),
              ASH_STATUS_OK);
    EXPECT_EQ(tier, ASH_TIER_FREE);

    /* 2. Attacker with Keypair B tries to hijack "prod-render-node" -> MUST FAIL */
    ash_msg_reg_v2_t m_evil = m_a;
    m_evil.ts_ms = 2000ULL;
    ash_reg_v2_sign(&m_evil, sec_b);
    EXPECT_EQ(ash_registry_on_reg_v2(&reg, &m_evil, &ep_evil, 0ULL, 1100000ULL, 2000ULL, &tier),
              ASH_STATUS_AUTH_FAILED);

    /* 3. Attacker tries v1 downgrade attack on pinned ID -> MUST FAIL */
    ash_rdv1_msg_t v1_evil;
    std::memset(&v1_evil, 0, sizeof(v1_evil));
    v1_evil.type = ASH_RDV1_REG;
    std::strcpy(v1_evil.name, "prod-render-node");
    EXPECT_EQ(ash_registry_on_reg_v1(&reg, &v1_evil, &ep_evil, 0ULL, 1200000ULL, nullptr),
              ASH_STATUS_AUTH_FAILED);

    /* 4. Replay of older timestamp with legitimate key -> REPLAY_REJECTED */
    ash_msg_reg_v2_t m_replay = m_a;
    m_replay.ts_ms = 500ULL;
    ash_reg_v2_sign(&m_replay, sec_a);
    EXPECT_EQ(ash_registry_on_reg_v2(&reg, &m_replay, &ep_a, 0ULL, 1300000ULL, 1300ULL, &tier),
              ASH_STATUS_REPLAY_REJECTED);

    /* Verify legitimate endpoint is untouched */
    ash_host_entry_t snap;
    ASSERT_TRUE(ash_registry_lookup_host(&reg, "prod-render-node", 1500000ULL, &snap));
    EXPECT_TRUE(ash_ep_eq(&snap.obs, &ep_a));

    ash_registry_destroy(&reg);

    /* 5. Restart Registry and reload keystore from disk -> Keypair B MUST still be rejected! */
    ash_registry_t reg_reloaded;
    ASSERT_TRUE(ash_registry_init(&reg_reloaded, 1024u, &cfg));
    EXPECT_EQ(ash_registry_on_reg_v2(&reg_reloaded, &m_evil, &ep_evil, 0ULL, 2000000ULL, 2000ULL, &tier),
              ASH_STATUS_AUTH_FAILED);
    m_a.ts_ms = 3000ULL;
    ash_reg_v2_sign(&m_a, sec_a);
    EXPECT_EQ(ash_registry_on_reg_v2(&reg_reloaded, &m_a, &ep_a, 0ULL, 2100000ULL, 3000ULL, &tier),
              ASH_STATUS_OK);

    ash_registry_destroy(&reg_reloaded);
    std::remove(ks_file);
}

/* AshDesk number ownership (docs/号码连接设计.md §4.2) at the registry: a 9-digit name belongs to the first key that proves
 * it; the proof answers a nonce issued to the sender's own address. */
TEST(RegistryAndAuth, NumberBelongsToItsFirstKeyAndTheProofIsBoundToTheSenderAddress) {
    const char *ks_file = "test_numbers_pin.db";
    std::remove(ks_file);

    ash_registry_cfg_t cfg;
    std::memset(&cfg, 0, sizeof(cfg));
    cfg.allow_v1_unauth = true;
    cfg.host_ttl_us     = 60000000ULL;
    cfg.keystore_path   = ks_file;
    ash_registry_t reg;
    ASSERT_TRUE(ash_registry_init(&reg, 1024u, &cfg));

    uint8_t seed_a[32], pub_a[32], sec_a[64];
    uint8_t seed_b[32], pub_b[32], sec_b[64];
    std::memset(seed_a, 0xA1, 32u);
    std::memset(seed_b, 0xB2, 32u);
    ash_ed25519_keypair(seed_a, pub_a, sec_a);
    ash_ed25519_keypair(seed_b, pub_b, sec_b);
    ash_ep_t ep_a, ep_a_moved, ep_evil;
    ASSERT_TRUE(ash_ep_parse("203.0.113.10:44100", 0u, &ep_a));
    ASSERT_TRUE(ash_ep_parse("203.0.113.77:51000", 0u, &ep_a_moved));
    ASSERT_TRUE(ash_ep_parse("198.51.100.99:55000", 0u, &ep_evil));

    ash_rdv1_msg_t plain;
    std::memset(&plain, 0, sizeof(plain));
    plain.type = ASH_RDV1_REG;
    std::strcpy(plain.name, "300000001");
    const auto reg_number = [&](ash_registry_t *r, const ash_rdv1_msg_t &m, const ash_ep_t &from, uint64_t now_us, bool *moved,
                                uint8_t *nonce) {
        return ash_registry_on_reg_number(r, &m, &from, 0ULL, now_us, true, moved, nullptr, nonce);
    };
    const auto online_at = [&](ash_registry_t *r, const ash_ep_t &ep, uint64_t now_us) {
        ash_host_entry_t snap;
        return ash_registry_lookup_host(r, "300000001", now_us, &snap) && ash_ep_eq(&snap.obs, &ep);
    };
    const uint64_t t0 = 1000000000ULL;
    const uint64_t second = 1000000ULL;
    uint8_t nonce_a[ASH_OWN_NONCE_LEN], nonce_evil[ASH_OWN_NONCE_LEN], unused[ASH_OWN_NONCE_LEN];
    bool moved = false;
    ash_host_entry_t snap;

    /* 1. No proof: a challenge, nothing registered. The nonce depends on the sender's address. */
    EXPECT_EQ(reg_number(&reg, plain, ep_a, t0, &moved, nonce_a), ASH_NUMBER_CHALLENGE);
    EXPECT_FALSE(ash_registry_lookup_host(&reg, "300000001", t0, &snap));
    EXPECT_EQ(reg_number(&reg, plain, ep_evil, t0, &moved, nonce_evil), ASH_NUMBER_CHALLENGE);
    EXPECT_NE(std::memcmp(nonce_a, nonce_evil, sizeof(nonce_a)), 0);

    /* 2. Key A proves the number: registered and pinned */
    ash_rdv1_msg_t proof_a = plain;
    ASSERT_TRUE(ash_rdv1_own_sign(&proof_a, nonce_a, pub_a, sec_a));
    EXPECT_EQ(reg_number(&reg, proof_a, ep_a, t0 + second, &moved, unused), ASH_NUMBER_REGISTERED);
    EXPECT_TRUE(moved);
    EXPECT_TRUE(online_at(&reg, ep_a, t0 + second));

    /* 2b. A sender out of its daily allowance cannot claim a number nobody owns; the ones it owns still register */
    ash_rdv1_msg_t fresh = plain;
    std::strcpy(fresh.name, "300000003");
    uint8_t nonce_fresh[ASH_OWN_NONCE_LEN];
    bool pinned = true;
    EXPECT_EQ(ash_registry_on_reg_number(&reg, &fresh, &ep_a, 0ULL, t0, false, &moved, &pinned, nonce_fresh), ASH_NUMBER_CHALLENGE);
    ASSERT_TRUE(ash_rdv1_own_sign(&fresh, nonce_fresh, pub_a, sec_a));
    EXPECT_EQ(ash_registry_on_reg_number(&reg, &fresh, &ep_a, 0ULL, t0 + second, false, &moved, &pinned, unused), ASH_NUMBER_LIMITED);
    EXPECT_FALSE(pinned);
    EXPECT_FALSE(ash_registry_lookup_host(&reg, "300000003", t0 + second, &snap));
    EXPECT_EQ(ash_registry_on_reg_number(&reg, &proof_a, &ep_a, 0ULL, t0 + 2u * second, false, &moved, &pinned, unused),
              ASH_NUMBER_REGISTERED);
    EXPECT_FALSE(pinned);
    EXPECT_EQ(ash_registry_on_reg_number(&reg, &fresh, &ep_a, 0ULL, t0 + 3u * second, true, &moved, &pinned, unused),
              ASH_NUMBER_REGISTERED);
    EXPECT_TRUE(pinned);
    EXPECT_TRUE(ash_registry_lookup_host(&reg, "300000003", t0 + 3u * second, &snap));

    /* 3. Keepalive from the unchanged address carries no proof */
    EXPECT_EQ(reg_number(&reg, plain, ep_a, t0 + 10u * second, &moved, unused), ASH_NUMBER_REGISTERED);
    EXPECT_FALSE(moved);

    /* 4. A's captured proof replayed from another address: its nonce was not issued there */
    EXPECT_EQ(reg_number(&reg, proof_a, ep_evil, t0 + 11u * second, &moved, unused), ASH_NUMBER_CHALLENGE);
    EXPECT_TRUE(online_at(&reg, ep_a, t0 + 11u * second));

    /* 5. Key B with a proper proof of its own: taken, the owner is untouched */
    ash_rdv1_msg_t proof_b = plain;
    ASSERT_TRUE(ash_rdv1_own_sign(&proof_b, nonce_evil, pub_b, sec_b));
    EXPECT_EQ(reg_number(&reg, proof_b, ep_evil, t0 + 12u * second, &moved, unused), ASH_NUMBER_TAKEN);
    EXPECT_TRUE(online_at(&reg, ep_a, t0 + 12u * second));

    /* 6. Right nonce, broken signature; and a proof signed for another number */
    ash_rdv1_msg_t broken = proof_b;
    broken.own_sig[3] ^= 0x40u;
    EXPECT_EQ(reg_number(&reg, broken, ep_evil, t0 + 13u * second, &moved, unused), ASH_NUMBER_BAD_PROOF);
    ash_rdv1_msg_t renamed = proof_b;
    std::strcpy(renamed.name, "300000002");
    EXPECT_EQ(reg_number(&reg, renamed, ep_evil, t0 + 13u * second, &moved, unused), ASH_NUMBER_BAD_PROOF);
    EXPECT_FALSE(ash_registry_lookup_host(&reg, "300000002", t0 + 13u * second, &snap));

    /* 7. The owner moves: a plain REG from the new address is challenged, the proof moves the number */
    uint8_t nonce_moved[ASH_OWN_NONCE_LEN];
    EXPECT_EQ(reg_number(&reg, plain, ep_a_moved, t0 + 20u * second, &moved, nonce_moved), ASH_NUMBER_CHALLENGE);
    EXPECT_TRUE(online_at(&reg, ep_a, t0 + 20u * second));
    ash_rdv1_msg_t proof_moved = plain;
    ASSERT_TRUE(ash_rdv1_own_sign(&proof_moved, nonce_moved, pub_a, sec_a));
    EXPECT_EQ(reg_number(&reg, proof_moved, ep_a_moved, t0 + 21u * second, &moved, unused), ASH_NUMBER_REGISTERED);
    EXPECT_TRUE(moved);
    EXPECT_TRUE(online_at(&reg, ep_a_moved, t0 + 21u * second));

    /* 8. A nonce lives for its own 60 s slice and the next one: the same proof 3 minutes later is challenged again */
    EXPECT_EQ(reg_number(&reg, proof_moved, ep_a_moved, t0 + 200u * second, &moved, unused), ASH_NUMBER_CHALLENGE);

    /* 9. The plain v1 path (unauthenticated names are allowed here) can never take a pinned number */
    EXPECT_EQ(ash_registry_on_reg_v1(&reg, &plain, &ep_evil, 0ULL, t0 + 201u * second, nullptr), ASH_STATUS_AUTH_FAILED);
    ash_registry_destroy(&reg);

    /* 10. Restart: the pin comes back from the keystore; nonces of the old process are void. A proved number is
     * authenticated, so it registers even with plain v1 names switched off. */
    cfg.allow_v1_unauth = false;
    ash_registry_t reloaded;
    ASSERT_TRUE(ash_registry_init(&reloaded, 1024u, &cfg));
    EXPECT_EQ(reg_number(&reloaded, proof_moved, ep_a_moved, t0 + 21u * second, &moved, unused), ASH_NUMBER_CHALLENGE);
    EXPECT_EQ(reg_number(&reloaded, plain, ep_evil, t0, &moved, nonce_evil), ASH_NUMBER_CHALLENGE);
    proof_b = plain;
    ASSERT_TRUE(ash_rdv1_own_sign(&proof_b, nonce_evil, pub_b, sec_b));
    EXPECT_EQ(reg_number(&reloaded, proof_b, ep_evil, t0 + second, &moved, unused), ASH_NUMBER_TAKEN);
    EXPECT_EQ(reg_number(&reloaded, plain, ep_a, t0, &moved, nonce_a), ASH_NUMBER_CHALLENGE);
    proof_a = plain;
    ASSERT_TRUE(ash_rdv1_own_sign(&proof_a, nonce_a, pub_a, sec_a));
    EXPECT_EQ(reg_number(&reloaded, proof_a, ep_a, t0 + second, &moved, unused), ASH_NUMBER_REGISTERED);
    EXPECT_TRUE(online_at(&reloaded, ep_a, t0 + second));
    ash_registry_destroy(&reloaded);
    std::remove(ks_file);

    /* 11. A full registry: no slot for a new number, and no answer to give */
    ash_registry_cfg_t tiny_cfg = cfg;
    tiny_cfg.keystore_path = nullptr;
    ash_registry_t tiny;
    ASSERT_TRUE(ash_registry_init(&tiny, 1u, &tiny_cfg));
    int registered = 0;
    int full = 0;
    for (uint32_t i = 0u; i < 2048u; ++i) {  /* 64 shards of 16 slots: twice what fits */
        ash_rdv1_msg_t one = plain;
        std::snprintf(one.name, sizeof(one.name), "%u", 400000000u + i);
        uint8_t nonce[ASH_OWN_NONCE_LEN];
        ASSERT_EQ(reg_number(&tiny, one, ep_a, t0, &moved, nonce), ASH_NUMBER_CHALLENGE);
        ASSERT_TRUE(ash_rdv1_own_sign(&one, nonce, pub_a, sec_a));
        const ash_number_result_t result = reg_number(&tiny, one, ep_a, t0 + second, &moved, unused);
        ASSERT_TRUE((result == ASH_NUMBER_REGISTERED) || (result == ASH_NUMBER_FULL));
        registered += (result == ASH_NUMBER_REGISTERED) ? 1 : 0;
        full += (result == ASH_NUMBER_FULL) ? 1 : 0;
    }
    EXPECT_GT(registered, 0);
    EXPECT_GT(full, 0);
    ash_registry_destroy(&tiny);
}

/* The daily allowance of newly claimed numbers is per source address (any port) and starts over the next day */
TEST(RegistryAndAuth, NewNumberAllowanceIsPerSourceAndPerDay) {
    ash_ip_guard_t guard;
    ASSERT_TRUE(ash_ip_guard_init(&guard, 1024u, 100u, 16u, 10000000ULL));
    ash_ep_t source, same_source_other_port, other_source;
    ASSERT_TRUE(ash_ep_parse("203.0.113.10:44100", 0u, &source));
    ASSERT_TRUE(ash_ep_parse("203.0.113.10:51000", 0u, &same_source_other_port));
    ASSERT_TRUE(ash_ep_parse("203.0.113.11:44100", 0u, &other_source));
    const uint64_t now_us = 5000000ULL;
    const uint16_t today = 20000u;

    /* No limit configured: nothing is counted */
    for (int i = 0; i < 5; ++i) {
        EXPECT_TRUE(ash_ip_guard_may_pin(&guard, &source, now_us, today));
        ash_ip_guard_note_pin(&guard, &source, now_us, today);
    }
    guard.max_pins_per_day = 2u;
    EXPECT_TRUE(ash_ip_guard_may_pin(&guard, &source, now_us, today));
    ash_ip_guard_note_pin(&guard, &source, now_us, today);
    EXPECT_TRUE(ash_ip_guard_may_pin(&guard, &source, now_us, today));
    ash_ip_guard_note_pin(&guard, &source, now_us, today);
    EXPECT_FALSE(ash_ip_guard_may_pin(&guard, &source, now_us, today));
    EXPECT_FALSE(ash_ip_guard_may_pin(&guard, &same_source_other_port, now_us, today));
    EXPECT_TRUE(ash_ip_guard_may_pin(&guard, &other_source, now_us, today));
    EXPECT_TRUE(ash_ip_guard_may_pin(&guard, &source, now_us, (uint16_t)(today + 1u)));

    /* IPv6: one allowance for a whole /48. Another /64 inside it, or another interface ID, is the same source */
    ash_ep_t subnet_a, subnet_b, other_site, zero_subnet;
    ASSERT_TRUE(ash_ep_parse("[2001:db8:1:a::5]:44100", 0u, &subnet_a));
    ASSERT_TRUE(ash_ep_parse("[2001:db8:1:b::77]:44100", 0u, &subnet_b));
    ASSERT_TRUE(ash_ep_parse("[2001:db8:2:a::5]:44100", 0u, &other_site));
    ASSERT_TRUE(ash_ep_parse("[2001:db8:1::9]:44100", 0u, &zero_subnet));
    ash_ip_guard_note_pin(&guard, &subnet_a, now_us, today);
    EXPECT_TRUE(ash_ip_guard_may_pin(&guard, &subnet_b, now_us, today));
    ash_ip_guard_note_pin(&guard, &subnet_b, now_us, today);
    EXPECT_FALSE(ash_ip_guard_may_pin(&guard, &subnet_a, now_us, today));
    EXPECT_FALSE(ash_ip_guard_may_pin(&guard, &subnet_b, now_us, today));
    EXPECT_FALSE(ash_ip_guard_may_pin(&guard, &zero_subnet, now_us, today));
    EXPECT_TRUE(ash_ip_guard_may_pin(&guard, &other_site, now_us, today));
    /* The rate limit and the penalty stay per /64: a strike against one subnet does not block its neighbour, and
     * running out of allowance blocks nobody */
    for (int i = 0; i < 16; ++i) ash_ip_guard_add_strike(&guard, &subnet_a, now_us);
    EXPECT_TRUE(ash_ip_guard_is_blocked(&guard, &subnet_a, now_us));
    EXPECT_FALSE(ash_ip_guard_is_blocked(&guard, &subnet_b, now_us));
    EXPECT_FALSE(ash_ip_guard_is_blocked(&guard, &zero_subnet, now_us));
    EXPECT_TRUE(ash_ip_guard_allow_sig(&guard, &zero_subnet, now_us));
    ash_ip_guard_destroy(&guard);
}

TEST(RegistryAndAuth, NatClassificationAndHolePunchStrategy) {
    ash_registry_cfg_t cfg;
    std::memset(&cfg, 0, sizeof(cfg));
    cfg.allow_v1_unauth = true;
    cfg.host_ttl_us     = 60000000ULL;

    ash_registry_t reg;
    ASSERT_TRUE(ash_registry_init(&reg, 256u, &cfg));

    ash_rdv1_msg_t r1;
    std::memset(&r1, 0, sizeof(r1));
    r1.type = ASH_RDV1_REG;
    std::strcpy(r1.name, "sym-host");
    r1.ncand = 1u;
    ASSERT_TRUE(ash_ep_parse("192.168.10.5:44100", 0u, &r1.cand[0]));

    ash_ep_t pub1, pub2_sym, same_wan_cli, other_wan_cli;
    ASSERT_TRUE(ash_ep_parse("198.51.100.10:30000", 0u, &pub1));
    ASSERT_TRUE(ash_ep_parse("198.51.100.10:30002", 0u, &pub2_sym));
    ASSERT_TRUE(ash_ep_parse("198.51.100.10:41234", 0u, &same_wan_cli));
    ASSERT_TRUE(ash_ep_parse("203.0.113.77:51000", 0u, &other_wan_cli));

    ASSERT_EQ(ash_registry_on_reg_v1(&reg, &r1, &pub1, 0ULL, 1000000ULL, nullptr), ASH_STATUS_OK);
    /* Secondary probe sees port +2 => Symmetric NAT with stride +2 */
    ash_registry_on_nat_probe(&reg, &pub2_sym, 1005000ULL);

    ash_host_entry_t host;
    ASSERT_TRUE(ash_registry_lookup_host(&reg, "sym-host", 1010000ULL, &host));
    EXPECT_EQ(host.nat_type, ASH_NAT_SYMMETRIC);
    EXPECT_EQ(host.port_stride, 2);

    /* Same public IP + LAN candidate => LAN Direct */
    EXPECT_EQ(ash_decide_punch_strategy(&host, &same_wan_cli, nullptr, 0u, ASH_NAT_SYMMETRIC, false),
              ASH_PUNCH_LAN_DIRECT);
    /* Dual Symmetric with small stride => UDP Symmetric Prediction */
    EXPECT_EQ(ash_decide_punch_strategy(&host, &other_wan_cli, nullptr, 0u, ASH_NAT_SYMMETRIC, false),
              ASH_PUNCH_UDP_SYM_PREDICT);
    /* Cone client + Symmetric host => UDP Cone Punch */
    EXPECT_EQ(ash_decide_punch_strategy(&host, &other_wan_cli, nullptr, 0u, ASH_NAT_OPEN_CONE, false),
              ASH_PUNCH_UDP_CONE);

    ash_registry_destroy(&reg);
}

TEST(CommercialRelay, FreeTierThrottlingVsVipHighSpeedIsolationAndStatelessHydration) {
    ash_relay_cfg_t cfg;
    std::memset(&cfg, 0, sizeof(cfg));
    cfg.sess_ttl_us          = 120000000ULL;
    cfg.stateless_window_min = 30u;
    cfg.tier_kbps[ASH_TIER_FREE] = 800u;     /* Free capped at 800 kbps (~100 KB/s, 10KB burst) */
    cfg.tier_kbps[ASH_TIER_VIP]  = 200000u;  /* VIP 200 Mbps */
    cfg.free_pool_total_kbps     = 800u;     /* Free pool strictly capped */
    cfg.total_bw_kbps            = 500000u;
    std::memset(cfg.cluster_secret, 0x77, sizeof(cfg.cluster_secret));

    ash_relay_table_t rt;
    ASSERT_TRUE(ash_relay_init(&rt, 1024u, &cfg));

    ash_ep_t h_ep, c_ep;
    ASSERT_TRUE(ash_ep_parse("10.1.1.1:44100", 0u, &h_ep));
    ASSERT_TRUE(ash_ep_parse("10.1.1.2:55100", 0u, &c_ep));

    /* Statelessly mint FREE and VIP sessions WITHOUT calling ash_relay_create_session! */
    uint32_t now_min = 1000u;
    uint32_t free_sess = ash_make_sess_id(ASH_TIER_FREE, now_min, 10u);
    uint32_t free_th = 0u, free_tc = 0u;
    ash_derive_sess_tokens(cfg.cluster_secret, free_sess, &free_th, &free_tc);

    uint32_t vip_sess = ash_make_sess_id(ASH_TIER_VIP, now_min, 11u);
    uint32_t vip_th = 0u, vip_tc = 0u;
    ash_derive_sess_tokens(cfg.cluster_secret, vip_sess, &vip_th, &vip_tc);

    uint8_t payload[1200];
    std::memset(payload, 0xCD, sizeof(payload));
    uint8_t pkt[ASH_RELAY_HDR_BYTES + sizeof(payload)];

    /* Prime client endpoints via stateless auto-hydration */
    size_t n = ash_relay_wrap(pkt, sizeof(pkt), free_sess, free_tc, payload, 64u);
    EXPECT_EQ(ash_relay_on_packet(&rt, pkt, n, &c_ep, 0ULL, 1000000ULL, now_min).kind, ASH_ROUTE_NONE);

    n = ash_relay_wrap(pkt, sizeof(pkt), vip_sess, vip_tc, payload, 64u);
    EXPECT_EQ(ash_relay_on_packet(&rt, pkt, n, &c_ep, 0ULL, 1000000ULL, now_min).kind, ASH_ROUTE_NONE);
    EXPECT_EQ(ash_atomic_load(&rt.stat_hydrated), 2ULL);

    /* Send 50 packets (60 KB) in 1 ms: Free must hit token bucket limit, VIP must pass 100%! */
    uint32_t free_passed = 0u, vip_passed = 0u;
    for (uint32_t i = 0u; i < 50u; ++i) {
        n = ash_relay_wrap(pkt, sizeof(pkt), free_sess, free_th, payload, sizeof(payload));
        if (ash_relay_on_packet(&rt, pkt, n, &h_ep, 0ULL, 1001000ULL + i, now_min).kind == ASH_ROUTE_UDP) {
            free_passed += 1u;
        }
        n = ash_relay_wrap(pkt, sizeof(pkt), vip_sess, vip_th, payload, sizeof(payload));
        ash_relay_route_t vr = ash_relay_on_packet(&rt, pkt, n, &h_ep, 0ULL, 1001000ULL + i, now_min);
        if (vr.kind == ASH_ROUTE_UDP) {
            vip_passed += 1u;
            /* Verify token bytes [5..8] were wiped to 0 before forwarding! */
            EXPECT_EQ(ash_get_be32(pkt + 5u), 0u);
        }
    }

    EXPECT_LT(free_passed, 15u);
    EXPECT_EQ(vip_passed, 50u);

    ash_relay_destroy(&rt);
}

TEST(ConcurrencyStress, MultiThreadedShardedRelayAndGuardRaceFree) {
    ash_relay_cfg_t cfg;
    std::memset(&cfg, 0, sizeof(cfg));
    cfg.sess_ttl_us = 60000000ULL;
    std::memset(cfg.cluster_secret, 0x33, sizeof(cfg.cluster_secret));

    ash_relay_table_t rt;
    ASSERT_TRUE(ash_relay_init(&rt, 4096u, &cfg));

    ash_ip_guard_t guard;
    ASSERT_TRUE(ash_ip_guard_init(&guard, 1024u, 500u, 10u, 5000000ULL));

    constexpr int kThreads = 6;
    std::vector<std::thread> workers;
    workers.reserve(kThreads);

    for (int t = 0; t < kThreads; ++t) {
        workers.emplace_back([&, t]() {
            ash_ep_t h_ep, c_ep;
            std::memset(&h_ep, 0, sizeof(h_ep));
            std::memset(&c_ep, 0, sizeof(c_ep));
            h_ep.fam = 4u; h_ep.ip[0] = 10u; h_ep.ip[1] = (uint8_t)t; h_ep.port = 10000u;
            c_ep.fam = 4u; c_ep.ip[0] = 10u; c_ep.ip[1] = (uint8_t)t; c_ep.port = 20000u;

            for (uint32_t i = 0u; i < 250u; ++i) {
                uint64_t now = 1000000ULL + i;
                (void)ash_ip_guard_allow_sig(&guard, &h_ep, now);

                uint32_t sess = 0u, th = 0u, tc = 0u;
                char hname[32];
                std::snprintf(hname, sizeof(hname), "mt-host-%d-%u", t, i & 31u);
                ASSERT_TRUE(ash_relay_create_session(&rt, hname, i + 1u, &h_ep, 0ULL, &c_ep, 0ULL,
                                                     ASH_TIER_PRO, 0u, 0u, now, 100u,
                                                     &sess, &th, &tc));
                uint8_t pl[64] = { 1, 2, 3, 4 };
                uint8_t pkt[ASH_RELAY_HDR_BYTES + sizeof(pl)];
                size_t len = ash_relay_wrap(pkt, sizeof(pkt), sess, th, pl, sizeof(pl));
                ash_relay_route_t r = ash_relay_on_packet(&rt, pkt, len, &h_ep, 0ULL, now, 100u);
                EXPECT_EQ(r.kind, ASH_ROUTE_UDP);
            }
        });
    }

    for (auto &th : workers) th.join();
    EXPECT_GE(ash_atomic_load(&rt.stat_fwd_pkts), (uint64_t)(kThreads * 250));

    ash_ip_guard_destroy(&guard);
    ash_relay_destroy(&rt);
}
