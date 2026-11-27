#include <gtest/gtest.h>

#include "ash_common.h"
#include "ash_crypto.h"
#include "ash_wire.h"

#include <cstring>
#include <vector>

TEST(CryptoPrimitives, SipHash24OfficialVector) {
    /* Official SipHash-2-4 paper vector (Aumasson & Bernstein) for 15-byte input 00..0e
     * with key 00..0f => 0xa129ca6149be45e5 */
    uint8_t key[16];
    uint8_t msg[15];
    for (uint8_t i = 0u; i < 16u; ++i) key[i] = i;
    for (uint8_t i = 0u; i < 15u; ++i) msg[i] = i;

    uint64_t h = ash_siphash24(key, msg, sizeof(msg));
    EXPECT_EQ(h, 0xa129ca6149be45e5ULL);
}

TEST(CryptoPrimitives, HmacSha256Rfc4231TestCase2) {
    /* RFC 4231 Test Case 2: Key = "Jefe", Data = "what do ya want for nothing?" */
    const char *key  = "Jefe";
    const char *data = "what do ya want for nothing?";
    uint8_t mac[ASH_SHA256_BYTES];
    ash_hmac_sha256(key, std::strlen(key), data, std::strlen(data), mac);

    char hex[65];
    ash_hex_encode(mac, sizeof(mac), hex);
    EXPECT_STREQ(hex, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}

TEST(CryptoPrimitives, Ed25519Rfc8032OfficialVectorsAndNonMalleability) {
    /* RFC 8032 §7.1 TEST 1 (empty message) */
    uint8_t seed1[32], exp_pub1[32], exp_sig1[64];
    ASSERT_TRUE(ash_hex_decode(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", seed1, 32u));
    ASSERT_TRUE(ash_hex_decode(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", exp_pub1, 32u));
    ASSERT_TRUE(ash_hex_decode(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b", exp_sig1, 64u));

    uint8_t pub1[32], sec1[64], sig1[64];
    ash_ed25519_keypair(seed1, pub1, sec1);
    EXPECT_EQ(std::memcmp(pub1, exp_pub1, 32u), 0);

    ash_ed25519_sign(sec1, nullptr, 0u, sig1);
    EXPECT_EQ(std::memcmp(sig1, exp_sig1, 64u), 0);
    EXPECT_TRUE(ash_ed25519_verify(pub1, nullptr, 0u, sig1));

    /* RFC 8032 §7.1 TEST 2 (1-byte message 0x72) */
    uint8_t seed2[32], exp_pub2[32], exp_sig2[64];
    ASSERT_TRUE(ash_hex_decode(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", seed2, 32u));
    ASSERT_TRUE(ash_hex_decode(
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", exp_pub2, 32u));
    ASSERT_TRUE(ash_hex_decode(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00", exp_sig2, 64u));

    uint8_t pub2[32], sec2[64], sig2[64];
    const uint8_t msg2[1] = { 0x72u };
    ash_ed25519_keypair(seed2, pub2, sec2);
    EXPECT_EQ(std::memcmp(pub2, exp_pub2, 32u), 0);
    ash_ed25519_sign(sec2, msg2, 1u, sig2);
    EXPECT_EQ(std::memcmp(sig2, exp_sig2, 64u), 0);
    EXPECT_TRUE(ash_ed25519_verify(pub2, msg2, 1u, sig2));

    /* Bit flip must fail verification */
    uint8_t bad_sig[64];
    std::memcpy(bad_sig, sig2, 64u);
    bad_sig[10] ^= 0x01u;
    EXPECT_FALSE(ash_ed25519_verify(pub2, msg2, 1u, bad_sig));

    /* Non-canonical scalar S >= L must fail verification */
    std::memcpy(bad_sig, sig2, 64u);
    std::memset(bad_sig + 32u, 0xFF, 32u);
    EXPECT_FALSE(ash_ed25519_verify(pub2, msg2, 1u, bad_sig));

    /* Non-canonical public key y >= 2^255 - 19 (0x7FFF...FFFE) must fail */
    uint8_t bad_pub[32];
    std::memset(bad_pub, 0xFF, 32u);
    bad_pub[31] = 0x7Fu;
    bad_pub[0]  = 0xEEu; /* 2^255 - 18 > p */
    EXPECT_FALSE(ash_ed25519_verify(bad_pub, msg2, 1u, sig2));
}

TEST(WireCodec, V1BackwardCompatibilityAndRelayFraming) {
    ash_rdv1_msg_t reg;
    std::memset(&reg, 0, sizeof(reg));
    reg.type = ASH_RDV1_REG;
    std::strcpy(reg.name, "studio-pc-01");
    reg.ncand = 2u;
    ASSERT_TRUE(ash_ep_parse("192.168.1.50:44100", 0u, &reg.cand[0]));
    ASSERT_TRUE(ash_ep_parse("[fe80::1234]:44100", 0u, &reg.cand[1]));
    reg.host_flags     = ASH_HF_DTLS_READY | ASH_HF_CAP_OK;
    reg.relay_max_kbps = 8000u;

    uint8_t wire[512];
    size_t n = ash_rdv1_build(wire, sizeof(wire), &reg);
    ASSERT_GT(n, 0u);
    EXPECT_EQ(wire[0], ASH_SIG_MAGIC);
    EXPECT_EQ(wire[1], ASH_RDV1_REG);

    ash_rdv1_msg_t parsed;
    ASSERT_TRUE(ash_rdv1_parse(wire, n, &parsed));
    EXPECT_EQ(parsed.type, ASH_RDV1_REG);
    EXPECT_STREQ(parsed.name, "studio-pc-01");
    EXPECT_EQ(parsed.ncand, 2u);
    EXPECT_TRUE(ash_ep_eq(&parsed.cand[0], &reg.cand[0]));
    EXPECT_TRUE(ash_ep_eq(&parsed.cand[1], &reg.cand[1]));
    EXPECT_EQ(parsed.host_flags, reg.host_flags);
    EXPECT_EQ(parsed.relay_max_kbps, 8000u);

    /* Relay wrap/unwrap */
    const uint8_t dtls_rec[12] = { 0x17, 0xFE, 0xFD, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    uint8_t rbuf[64];
    size_t rn = ash_relay_wrap(rbuf, sizeof(rbuf), 0x11223344u, 0x55667788u, dtls_rec, sizeof(dtls_rec));
    ASSERT_EQ(rn, ASH_RELAY_HDR_BYTES + sizeof(dtls_rec));

    uint32_t sess = 0u, tok = 0u;
    size_t pl = ash_relay_unwrap(rbuf, rn, &sess, &tok);
    EXPECT_EQ(pl, sizeof(dtls_rec));
    EXPECT_EQ(sess, 0x11223344u);
    EXPECT_EQ(tok, 0x55667788u);
    EXPECT_EQ(std::memcmp(rbuf + ASH_RELAY_HDR_BYTES, dtls_rec, sizeof(dtls_rec)), 0);
}

/* Presence (AshDesk M1): the shortest request is 8 B; both replies must be shorter so the server cannot amplify. */
TEST(WireCodec, V1PresenceRepliesAreShorterThanAnyRequest) {
    ash_rdv1_msg_t q;
    std::memset(&q, 0, sizeof(q));
    q.type = ASH_RDV1_PRESENCE;
    q.req  = 0x0A0B0C0Du;
    std::strcpy(q.name, "x");
    uint8_t wire[64];
    size_t n = ash_rdv1_build(wire, sizeof(wire), &q);
    ASSERT_EQ(n, 8u);
    ash_rdv1_msg_t parsed;
    ASSERT_TRUE(ash_rdv1_parse(wire, n, &parsed));
    EXPECT_EQ(parsed.type, ASH_RDV1_PRESENCE);
    EXPECT_EQ(parsed.req, q.req);
    EXPECT_STREQ(parsed.name, "x");
    EXPECT_FALSE(ash_rdv1_parse(wire, n - 1u, &parsed));
    q.name[0] = '\0';
    EXPECT_EQ(ash_rdv1_build(wire, sizeof(wire), &q), 0u);

    ash_rdv1_msg_t ok;
    std::memset(&ok, 0, sizeof(ok));
    ok.type       = ASH_RDV1_PRESENCE_OK;
    ok.req        = 9u;
    ok.host_flags = ASH_HF_BUSY | ASH_HF_ATTENDED;
    n = ash_rdv1_build(wire, sizeof(wire), &ok);
    ASSERT_EQ(n, 7u);
    EXPECT_EQ(wire[6], ASH_HF_BUSY | ASH_HF_ATTENDED);
    ASSERT_TRUE(ash_rdv1_parse(wire, n, &parsed));
    EXPECT_EQ(parsed.type, ASH_RDV1_PRESENCE_OK);
    EXPECT_EQ(parsed.host_flags, ok.host_flags);
    EXPECT_EQ(parsed.relay_max_kbps, 0u);
    EXPECT_FALSE(ash_rdv1_parse(wire, n - 1u, &parsed));   /* flags byte missing */
    EXPECT_FALSE(ash_rdv1_parse(wire, n + 1u, &parsed));   /* trailing byte */
    ok.host_flags = 0u;
    EXPECT_EQ(ash_rdv1_build(wire, sizeof(wire), &ok), 7u);  /* flags is a body byte even when zero */
    wire[7] = ASH_EXT_MAGIC;                                 /* the 6 B extension is not accepted here */
    std::memset(wire + 8, 0, 5);
    EXPECT_FALSE(ash_rdv1_parse(wire, 13u, &parsed));

    ash_rdv1_msg_t nf;
    std::memset(&nf, 0, sizeof(nf));
    nf.type = ASH_RDV1_NOTFOUND;
    nf.req  = 9u;
    EXPECT_EQ(ash_rdv1_build(wire, sizeof(wire), &nf), 6u);
}

/* Golden bytes printed by AshDesk's own rdv_build (proto/common/adp_rdv.c) for the same three messages */
TEST(WireCodec, V1NatMessagesMatchAshDeskByteForByte) {
    const uint8_t ashdesk_test[] = { 0x53, 0x07, 0x00, 0x00, 0x00, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    const uint8_t ashdesk_ok[]   = { 0x53, 0x08, 0x00, 0x00, 0x00, 0x01, 0x01, 0x04, 0xCB, 0x00, 0x71, 0x07, 0x9C, 0x41 };
    const uint8_t ashdesk_peer[] = { 0x53, 0x09, 0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x00, 0x00, 0x02, 0x04, 0xC6,
                                     0x33, 0x64, 0x09, 0xC3, 0x50, 0x04, 0xC6, 0x33, 0x64, 0x09, 0xC3, 0x54 };
    uint8_t wire[64];
    ash_rdv1_msg_t m;

    ASSERT_TRUE(ash_rdv1_parse(ashdesk_test, sizeof(ashdesk_test), &m));
    EXPECT_EQ(m.type, ASH_RDV1_NAT_TEST);
    EXPECT_EQ(m.req, 2u);
    EXPECT_EQ(m.sess, 0x11223344u);
    EXPECT_EQ(m.tok, 0x55667788u);
    EXPECT_FALSE(ash_rdv1_parse(ashdesk_test, sizeof(ashdesk_test) - 1u, &m));  /* token cut short */

    std::memset(&m, 0, sizeof(m));
    m.type  = ASH_RDV1_NAT_OK;
    m.req   = 1u;
    m.ncand = 1u;
    ASSERT_TRUE(ash_ep_parse("203.0.113.7:40001", 0u, &m.cand[0]));
    size_t n = ash_rdv1_build(wire, sizeof(wire), &m);
    ASSERT_EQ(n, sizeof(ashdesk_ok));
    EXPECT_EQ(std::memcmp(wire, ashdesk_ok, n), 0);

    std::memset(&m, 0, sizeof(m));
    m.type  = ASH_RDV1_NAT_PEER;
    m.sess  = 0x11223344u;
    m.ncand = 2u;
    ASSERT_TRUE(ash_ep_parse("198.51.100.9:50000", 0u, &m.cand[0]));
    ASSERT_TRUE(ash_ep_parse("198.51.100.9:50004", 0u, &m.cand[1]));
    n = ash_rdv1_build(wire, sizeof(wire), &m);
    ASSERT_EQ(n, sizeof(ashdesk_peer));
    EXPECT_EQ(std::memcmp(wire, ashdesk_peer, n), 0);

    ash_rdv1_msg_t back;
    ASSERT_TRUE(ash_rdv1_parse(ashdesk_peer, sizeof(ashdesk_peer), &back));
    EXPECT_EQ(back.ncand, 2u);
    EXPECT_EQ(back.cand[1].port, 50004u);
    uint8_t three[sizeof(ashdesk_peer)];
    std::memcpy(three, ashdesk_peer, sizeof(three));
    three[10] = 3u;                                                       /* says 3 candidates, carries 2 */
    EXPECT_FALSE(ash_rdv1_parse(three, sizeof(three), &back));
    uint8_t junk[sizeof(ashdesk_ok) + 1u];
    std::memcpy(junk, ashdesk_ok, sizeof(ashdesk_ok));
    junk[sizeof(ashdesk_ok)] = 0x00u;                                     /* trailing byte */
    EXPECT_FALSE(ash_rdv1_parse(junk, sizeof(junk), &back));
}

/* AshDesk number ownership (docs/号码连接设计.md §4.2): REG proof extension, REG_CHAL, REG_TAKEN. The signature vector is
 * the one in AshDesk's tests/test_proto.c (OpenSSL) and tools/rdv_probe.py (RFC 8032 reference code): three independent
 * implementations must agree on the signed message byte for byte. */
TEST(WireCodec, V1NumberOwnershipProofChallengeAndTaken) {
    EXPECT_EQ(ash_rdv1_number_value("123456789"), 123456789u);
    EXPECT_EQ(ash_rdv1_number_value("999999999"), 999999999u);
    for (const char *not_a_number : { "023456789", "12345678", "1234567890", "12345678a", "office-pc", "" }) {
        EXPECT_EQ(ash_rdv1_number_value(not_a_number), 0u) << not_a_number;
    }

    ash_rdv1_msg_t reg, got;
    std::memset(&reg, 0, sizeof(reg));
    reg.type  = ASH_RDV1_REG;
    reg.ncand = 1u;
    std::strcpy(reg.name, "123456789");
    ASSERT_TRUE(ash_ep_parse("10.0.0.2:44100", 0u, &reg.cand[0]));
    uint8_t buf[512];
    const size_t plain = ash_rdv1_build(buf, sizeof(buf), &reg);
    ASSERT_EQ(plain, 2u + 1u + 9u + 1u + 7u);  /* Without a proof the REG is the legacy one, byte for byte */
    ASSERT_TRUE(ash_rdv1_parse(buf, plain, &got));
    EXPECT_EQ(got.has_own, 0u);

    /* RFC 8032 §7.1 TEST 1 key; nonce 01..08; name 123456789 */
    const uint8_t seed[32] = { 0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
                               0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60 };
    const uint8_t nonce[ASH_OWN_NONCE_LEN] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    const uint8_t expected_sig[ASH_ED25519_SIG_LEN] = {
        0xb2, 0x6c, 0x12, 0x2b, 0x26, 0x8b, 0x37, 0x3f, 0xc5, 0xde, 0xb2, 0x71, 0x10, 0xd9, 0xcc, 0xb2,
        0x91, 0xc5, 0x37, 0xc7, 0x28, 0xbd, 0xa4, 0x7a, 0x2b, 0xc4, 0x07, 0x51, 0xad, 0x7a, 0x51, 0x9c,
        0xcf, 0x95, 0x5e, 0xad, 0x56, 0x5c, 0x5d, 0x73, 0xfa, 0xf1, 0x46, 0x9d, 0x23, 0xd9, 0x7a, 0xa6,
        0xb8, 0x47, 0xe9, 0x7d, 0x1a, 0xad, 0x6f, 0xb7, 0x04, 0xb7, 0x9f, 0x7a, 0xc8, 0x7f, 0x9c, 0x00 };
    uint8_t pub[ASH_ED25519_PUB_LEN], sec[ASH_ED25519_SEC_LEN];
    ash_ed25519_keypair(seed, pub, sec);
    ASSERT_TRUE(ash_rdv1_own_sign(&reg, nonce, pub, sec));
    EXPECT_EQ(std::memcmp(reg.own_sig, expected_sig, sizeof(expected_sig)), 0);
    EXPECT_TRUE(ash_rdv1_own_verify(&reg));

    const size_t n = ash_rdv1_build(buf, sizeof(buf), &reg);
    ASSERT_EQ(n, plain + ASH_OWN_EXT_BYTES);
    EXPECT_EQ(buf[plain], ASH_OWN_EXT);
    ASSERT_TRUE(ash_rdv1_parse(buf, n, &got));
    EXPECT_EQ(got.has_own, 1u);
    EXPECT_EQ(std::memcmp(got.own_pub, pub, sizeof(pub)), 0);
    EXPECT_EQ(std::memcmp(got.own_nonce, nonce, sizeof(nonce)), 0);
    EXPECT_EQ(std::memcmp(got.own_sig, expected_sig, sizeof(expected_sig)), 0);
    EXPECT_TRUE(ash_rdv1_own_verify(&got));
    EXPECT_FALSE(ash_rdv1_parse(buf, n - 1u, &got));  /* Truncated proof */
    buf[n] = 0u;
    EXPECT_FALSE(ash_rdv1_parse(buf, n + 1u, &got));  /* Trailing byte */
    buf[plain] = 0xE3u;
    EXPECT_FALSE(ash_rdv1_parse(buf, n, &got));       /* Unknown extension marker */

    /* The proof covers nonce and name, and belongs to one key */
    ash_rdv1_msg_t bad = reg;
    bad.name[8] = '0';
    EXPECT_FALSE(ash_rdv1_own_verify(&bad));
    bad = reg;
    bad.own_nonce[7] ^= 1u;
    EXPECT_FALSE(ash_rdv1_own_verify(&bad));
    bad = reg;
    bad.own_sig[10] ^= 1u;
    EXPECT_FALSE(ash_rdv1_own_verify(&bad));
    bad = reg;
    bad.own_pub[0] ^= 1u;
    EXPECT_FALSE(ash_rdv1_own_verify(&bad));
    bad = reg;
    bad.has_own = 0u;
    EXPECT_FALSE(ash_rdv1_own_verify(&bad));
    bad = reg;
    bad.name[0] = '\0';
    EXPECT_FALSE(ash_rdv1_own_sign(&bad, nonce, pub, sec));

    /* Both extensions: host flags first (0x10 is AshDesk's "accepts connection passwords"), then the proof */
    reg.host_flags = ASH_HF_DTLS_READY | ASH_HF_PASSWORD;
    const size_t both = ash_rdv1_build(buf, sizeof(buf), &reg);
    ASSERT_EQ(both, plain + 6u + ASH_OWN_EXT_BYTES);
    EXPECT_EQ(buf[plain], ASH_EXT_MAGIC);
    EXPECT_EQ(buf[plain + 6u], ASH_OWN_EXT);
    ASSERT_TRUE(ash_rdv1_parse(buf, both, &got));
    EXPECT_EQ(got.host_flags, ASH_HF_DTLS_READY | ASH_HF_PASSWORD);
    EXPECT_EQ(got.has_own, 1u);

    /* Only REG carries a proof */
    ash_rdv1_msg_t lookup = reg;
    lookup.type       = ASH_RDV1_LOOKUP;
    lookup.host_flags = 0u;
    const size_t ln = ash_rdv1_build(buf, sizeof(buf), &lookup);
    ASSERT_EQ(ln, 2u + 4u + 1u + 9u + 1u + 7u);
    buf[ln] = ASH_OWN_EXT;
    std::memset(buf + ln + 1u, 7, ASH_OWN_EXT_BYTES - 1u);
    EXPECT_FALSE(ash_rdv1_parse(buf, ln + ASH_OWN_EXT_BYTES, &got));

    /* REG_CHAL (10 B) and REG_TAKEN (12 B) are shorter than the shortest REG for a number (13 B): no amplification */
    ash_rdv1_msg_t chal;
    std::memset(&chal, 0, sizeof(chal));
    chal.type = ASH_RDV1_REG_CHAL;
    std::memcpy(chal.own_nonce, nonce, sizeof(nonce));
    const size_t cn = ash_rdv1_build(buf, sizeof(buf), &chal);
    ASSERT_EQ(cn, 10u);
    ASSERT_TRUE(ash_rdv1_parse(buf, cn, &got));
    EXPECT_EQ(got.type, ASH_RDV1_REG_CHAL);
    EXPECT_EQ(std::memcmp(got.own_nonce, nonce, sizeof(nonce)), 0);
    EXPECT_EQ(got.has_own, 0u);
    EXPECT_FALSE(ash_rdv1_parse(buf, cn - 1u, &got));
    buf[cn] = 0u;
    EXPECT_FALSE(ash_rdv1_parse(buf, cn + 1u, &got));

    ash_rdv1_msg_t taken;
    std::memset(&taken, 0, sizeof(taken));
    taken.type = ASH_RDV1_REG_TAKEN;
    std::strcpy(taken.name, "123456789");
    const size_t tn = ash_rdv1_build(buf, sizeof(buf), &taken);
    ASSERT_EQ(tn, 12u);
    ASSERT_TRUE(ash_rdv1_parse(buf, tn, &got));
    EXPECT_EQ(got.type, ASH_RDV1_REG_TAKEN);
    EXPECT_STREQ(got.name, "123456789");
    EXPECT_FALSE(ash_rdv1_parse(buf, tn - 1u, &got));
    taken.name[0] = '\0';
    EXPECT_EQ(ash_rdv1_build(buf, sizeof(buf), &taken), 0u);
}

TEST(WireCodec, V2AuthLicenseTicketAndTcp443Framing) {
    uint8_t lic_sec[32], clus_sec[32];
    std::memset(lic_sec, 0x42, sizeof(lic_sec));
    std::memset(clus_sec, 0x99, sizeof(clus_sec));

    ash_license_claims_t lc;
    lc.tier         = ASH_TIER_VIP;
    lc.pool_id      = 7u;
    lc.max_kbps     = 80000u;
    lc.expire_ms    = 2000000000000ULL;
    lc.subject_hash = ash_device_hash32("vip-workstation");

    uint8_t lic_raw[ASH_LICENSE_BYTES];
    ash_license_sign(lic_sec, &lc, lic_raw);

    ash_license_claims_t lc_out;
    ASSERT_TRUE(ash_license_verify(lic_sec, lic_raw, "vip-workstation", 1900000000000ULL, &lc_out));
    EXPECT_EQ(lc_out.tier, ASH_TIER_VIP);
    EXPECT_EQ(lc_out.pool_id, 7u);
    EXPECT_EQ(lc_out.max_kbps, 80000u);
    /* Wrong device name or expired timestamp must fail */
    EXPECT_FALSE(ash_license_verify(lic_sec, lic_raw, "other-pc", 1900000000000ULL, &lc_out));
    EXPECT_FALSE(ash_license_verify(lic_sec, lic_raw, "vip-workstation", 2100000000000ULL, &lc_out));

    /* v2 Signed Registration */
    uint8_t seed[32], pub[32], sec[64];
    std::memset(seed, 0x11, sizeof(seed));
    ash_ed25519_keypair(seed, pub, sec);

    ash_msg_reg_v2_t r2;
    std::memset(&r2, 0, sizeof(r2));
    r2.nat_type    = ASH_NAT_OPEN_CONE;
    r2.host_flags  = ASH_HF_DTLS_READY | ASH_HF_TCP_PUNCH;
    r2.tcp_port    = 44100u;
    r2.ts_ms       = 1700000000123ULL;
    std::strcpy(r2.name, "vip-workstation");
    r2.ncand = 1u;
    ASSERT_TRUE(ash_ep_parse("10.0.0.8:44100", 0u, &r2.cand[0]));
    r2.has_license = true;
    std::memcpy(r2.license, lic_raw, ASH_LICENSE_BYTES);
    ash_reg_v2_sign(&r2, sec);
    ASSERT_TRUE(ash_reg_v2_verify_sig(&r2));

    uint8_t buf[512];
    size_t r2_len = ash_build_reg_v2(buf, sizeof(buf), &r2);
    ASSERT_GT(r2_len, 0u);

    ash_msg_reg_v2_t r2_dec;
    ASSERT_TRUE(ash_parse_reg_v2(buf, r2_len, &r2_dec));
    EXPECT_TRUE(ash_reg_v2_verify_sig(&r2_dec));
    EXPECT_EQ(r2_dec.tcp_port, 44100u);
    EXPECT_TRUE(r2_dec.has_license);

    /* Tamper with host_flags -> Ed25519 verification must fail */
    r2_dec.host_flags ^= 0x04u;
    EXPECT_FALSE(ash_reg_v2_verify_sig(&r2_dec));

    /* TCP 443 Framing: HTTP Upgrade preface + split-stream TLS AppData & RFC 4571 */
    const char *http_upg =
        "GET /ashdesk-relay HTTP/1.1\r\nHost: relay.example.com\r\nUpgrade: ashdesk-relay/1\r\n\r\n";
    uint8_t stream[512];
    size_t slen = std::strlen(http_upg);
    std::memcpy(stream, http_upg, slen);
    size_t f1 = ash_tcp_frame_encode(ASH_TCP_FRAME_RFC4571, buf, r2_len,
                                     stream + slen, sizeof(stream) - slen);
    ASSERT_GT(f1, 0u);
    size_t total = slen + f1;

    ash_tcp_frame_mode_t mode = ASH_TCP_FRAME_UNKNOWN;
    const uint8_t *pl = nullptr;
    size_t pl_len = 0u;
    bool need_101 = false;

    /* Partial HTTP header returns 0 (need more bytes) */
    EXPECT_EQ(ash_tcp_frame_decode(&mode, stream, 12u, &pl, &pl_len, &need_101), 0);
    int c1 = ash_tcp_frame_decode(&mode, stream, total, &pl, &pl_len, &need_101);
    ASSERT_EQ(c1, (int)slen);
    EXPECT_TRUE(need_101);
    EXPECT_EQ(mode, ASH_TCP_FRAME_RFC4571);

    /* Partial payload returns 0 */
    EXPECT_EQ(ash_tcp_frame_decode(&mode, stream + slen, 5u, &pl, &pl_len, &need_101), 0);
    int c2 = ash_tcp_frame_decode(&mode, stream + slen, f1, &pl, &pl_len, &need_101);
    ASSERT_EQ(c2, (int)f1);
    ASSERT_EQ(pl_len, r2_len);
    EXPECT_EQ(std::memcmp(pl, buf, r2_len), 0);

    /* TLS 0x17 0x03 0x03 ApplicationData record mode */
    uint8_t tls_stream[512];
    size_t tf = ash_tcp_frame_encode(ASH_TCP_FRAME_TLS_APP, buf, r2_len, tls_stream, sizeof(tls_stream));
    ASSERT_EQ(tf, 5u + r2_len);
    ash_tcp_frame_mode_t tls_mode = ASH_TCP_FRAME_UNKNOWN;
    int tc = ash_tcp_frame_decode(&tls_mode, tls_stream, tf, &pl, &pl_len, &need_101);
    ASSERT_EQ(tc, (int)tf);
    EXPECT_EQ(tls_mode, ASH_TCP_FRAME_TLS_APP);
    EXPECT_EQ(pl_len, r2_len);
}
