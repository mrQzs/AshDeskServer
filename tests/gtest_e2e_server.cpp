#include <gtest/gtest.h>

#include "ash_server.h"

#include <chrono>
#include <cstring>
#include <string>
#include <thread>

namespace {

ash_sock_t open_blocking_udp(uint16_t *out_port) {
    ash_sock_t s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == ASH_INVALID_SOCK) return ASH_INVALID_SOCK;
#ifdef _WIN32
    DWORD tv = 1500;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
#else
    struct timeval tv = { 1, 500000 };
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
    struct sockaddr_in sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port        = 0;
    if (bind(s, (const struct sockaddr *)&sa, sizeof(sa)) != 0) {
        ash_sock_close(s);
        return ASH_INVALID_SOCK;
    }
    if (out_port != nullptr) *out_port = ash_sock_bound_port(s);
    return s;
}

ash_sock_t connect_blocking_tcp(uint16_t port) {
    ash_sock_t s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == ASH_INVALID_SOCK) return ASH_INVALID_SOCK;
#ifdef _WIN32
    DWORD tv = 1500;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
#else
    struct timeval tv = { 1, 500000 };
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
    struct sockaddr_in sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port        = htons(port);
    if (connect(s, (const struct sockaddr *)&sa, sizeof(sa)) != 0) {
        ash_sock_close(s);
        return ASH_INVALID_SOCK;
    }
    return s;
}

bool send_all_tcp(ash_sock_t s, const uint8_t *buf, size_t len) {
    size_t off = 0u;
    while (off < len) {
#ifdef _WIN32
        int n = send(s, (const char *)(buf + off), (int)(len - off), 0);
#else
        int n = (int)send(s, buf + off, len - off, 0);
#endif
        if (n <= 0) return false;
        off += (size_t)n;
    }
    return true;
}

bool recv_exact_tcp(ash_sock_t s, uint8_t *buf, size_t len) {
    size_t off = 0u;
    while (off < len) {
#ifdef _WIN32
        int n = recv(s, (char *)(buf + off), (int)(len - off), 0);
#else
        int n = (int)recv(s, buf + off, len - off, 0);
#endif
        if (n <= 0) return false;
        off += (size_t)n;
    }
    return true;
}

class ServerEnv : public ::testing::Test {
protected:
    void SetUp() override { ASSERT_TRUE(ash_net_init()); }
    void TearDown() override { ash_net_cleanup(); }
};

}  // namespace

TEST_F(ServerEnv, V1AshDeskClientDropInSignalingRelayAndNatRebind) {
    ash_server_cfg_t cfg;
    ash_server_cfg_defaults(&cfg);
    cfg.bind_ip   = "127.0.0.1";
    cfg.udp_port  = 0u;
    cfg.free_kbps = 12000u;

    ash_server_t *srv = ash_server_create(&cfg);
    ASSERT_NE(srv, nullptr);
    ASSERT_TRUE(ash_server_start(srv));

    struct sockaddr_in srv_sa;
    std::memset(&srv_sa, 0, sizeof(srv_sa));
    srv_sa.sin_family      = AF_INET;
    srv_sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    srv_sa.sin_port        = htons(ash_server_udp_port(srv));

    uint16_t h_port = 0u, c_port = 0u;
    ash_sock_t h_sock = open_blocking_udp(&h_port);
    ash_sock_t c_sock = open_blocking_udp(&c_port);
    ASSERT_NE(h_sock, ASH_INVALID_SOCK);
    ASSERT_NE(c_sock, ASH_INVALID_SOCK);

    /* 1. Host sends adp_rdv v1 RDV_REG */
    ash_rdv1_msg_t reg;
    std::memset(&reg, 0, sizeof(reg));
    reg.type       = ASH_RDV1_REG;
    reg.host_flags = ASH_HF_DTLS_READY | ASH_HF_CAP_OK;
    std::strcpy(reg.name, "ashdesk-v1-host");
    reg.ncand = 1u;
    ASSERT_TRUE(ash_ep_parse("192.168.50.10:44100", 0u, &reg.cand[0]));

    uint8_t buf[512], rx[512];
    size_t n = ash_rdv1_build(buf, sizeof(buf), &reg);
    ASSERT_EQ((int)sendto(h_sock, (const char *)buf, (ash_io_len_t)n, 0,
                          (const struct sockaddr *)&srv_sa, sizeof(srv_sa)), (int)n);

    int r = (int)recvfrom(h_sock, (char *)rx, (ash_io_len_t)sizeof(rx), 0, nullptr, nullptr);
    ASSERT_GT(r, 0);
    ash_rdv1_msg_t reg_ok;
    ASSERT_TRUE(ash_rdv1_parse(rx, (size_t)r, &reg_ok));
    EXPECT_EQ(reg_ok.type, ASH_RDV1_REG_OK);
    ASSERT_EQ(reg_ok.ncand, 1u);
    EXPECT_EQ(reg_ok.cand[0].port, h_port);

    /* 2. Client sends adp_rdv v1 RDV_LOOKUP */
    ash_rdv1_msg_t lk;
    std::memset(&lk, 0, sizeof(lk));
    lk.type = ASH_RDV1_LOOKUP;
    lk.req  = 0xAABBCCDDu;
    std::strcpy(lk.name, "ashdesk-v1-host");
    n = ash_rdv1_build(buf, sizeof(buf), &lk);
    ASSERT_EQ((int)sendto(c_sock, (const char *)buf, (ash_io_len_t)n, 0,
                          (const struct sockaddr *)&srv_sa, sizeof(srv_sa)), (int)n);

    r = (int)recvfrom(c_sock, (char *)rx, (ash_io_len_t)sizeof(rx), 0, nullptr, nullptr);
    ASSERT_GT(r, 0);
    ash_rdv1_msg_t conn_msg;
    ASSERT_TRUE(ash_rdv1_parse(rx, (size_t)r, &conn_msg));
    EXPECT_EQ(conn_msg.type, ASH_RDV1_CONN);
    EXPECT_EQ(conn_msg.req, 0xAABBCCDDu);
    EXPECT_EQ(conn_msg.relay_max_kbps, 12000u);
    EXPECT_EQ(conn_msg.host_flags, reg.host_flags);
    ASSERT_EQ(conn_msg.ncand, 2u);
    EXPECT_EQ(conn_msg.cand[0].port, h_port);

    r = (int)recvfrom(h_sock, (char *)rx, (ash_io_len_t)sizeof(rx), 0, nullptr, nullptr);
    ASSERT_GT(r, 0);
    ash_rdv1_msg_t inc_msg;
    ASSERT_TRUE(ash_rdv1_parse(rx, (size_t)r, &inc_msg));
    EXPECT_EQ(inc_msg.type, ASH_RDV1_INCOMING);
    EXPECT_EQ(inc_msg.sess, conn_msg.sess);

    /* 3. Client changes NAT source port (simulating 4G/Wi-Fi switch) & sends Relay packet */
    uint16_t c_new_port = 0u;
    ash_sock_t c_rebound = open_blocking_udp(&c_new_port);
    ASSERT_NE(c_rebound, ASH_INVALID_SOCK);

    const char *msg_c2h = "DTLS-CLIENT-HELLO-REBOUND";
    n = ash_relay_wrap(buf, sizeof(buf), conn_msg.sess, conn_msg.tok,
                       (const uint8_t *)msg_c2h, std::strlen(msg_c2h));
    ASSERT_EQ((int)sendto(c_rebound, (const char *)buf, (ash_io_len_t)n, 0,
                          (const struct sockaddr *)&srv_sa, sizeof(srv_sa)), (int)n);

    r = (int)recvfrom(h_sock, (char *)rx, (ash_io_len_t)sizeof(rx), 0, nullptr, nullptr);
    ASSERT_EQ(r, (int)n);
    uint32_t rx_sess = 0u, rx_tok = 99u;
    size_t pl = ash_relay_unwrap(rx, (size_t)r, &rx_sess, &rx_tok);
    EXPECT_EQ(rx_sess, conn_msg.sess);
    EXPECT_EQ(rx_tok, 0u); /* Token zeroed by Relay! */
    EXPECT_EQ(std::memcmp(rx + ASH_RELAY_HDR_BYTES, msg_c2h, pl), 0);

    /* Host replies -> Relay must deliver to c_rebound (the new port!), NOT old c_sock! */
    const char *msg_h2c = "DTLS-SERVER-HELLO-REPLY";
    n = ash_relay_wrap(buf, sizeof(buf), inc_msg.sess, inc_msg.tok,
                       (const uint8_t *)msg_h2c, std::strlen(msg_h2c));
    ASSERT_EQ((int)sendto(h_sock, (const char *)buf, (ash_io_len_t)n, 0,
                          (const struct sockaddr *)&srv_sa, sizeof(srv_sa)), (int)n);

    r = (int)recvfrom(c_rebound, (char *)rx, (ash_io_len_t)sizeof(rx), 0, nullptr, nullptr);
    ASSERT_EQ(r, (int)n);
    pl = ash_relay_unwrap(rx, (size_t)r, &rx_sess, &rx_tok);
    EXPECT_EQ(std::memcmp(rx + ASH_RELAY_HDR_BYTES, msg_h2c, pl), 0);

    ash_sock_close(c_rebound);
    ash_sock_close(c_sock);
    ash_sock_close(h_sock);
    ash_server_destroy(srv);
}

/* Presence (AshDesk M1): online + host flags, or NOTFOUND; never creates a session or notifies the host; malformed -> silence. */
TEST_F(ServerEnv, V1PresenceAnswersWithoutWakingTheHost) {
    ash_server_cfg_t cfg;
    ash_server_cfg_defaults(&cfg);
    cfg.bind_ip  = "127.0.0.1";
    cfg.udp_port = 0u;
    ash_server_t *srv = ash_server_create(&cfg);
    ASSERT_NE(srv, nullptr);
    ASSERT_TRUE(ash_server_start(srv));
    struct sockaddr_in srv_sa;
    std::memset(&srv_sa, 0, sizeof(srv_sa));
    srv_sa.sin_family      = AF_INET;
    srv_sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    srv_sa.sin_port        = htons(ash_server_udp_port(srv));
    ash_sock_t h_sock = open_blocking_udp(nullptr);
    ash_sock_t c_sock = open_blocking_udp(nullptr);
    ASSERT_NE(h_sock, ASH_INVALID_SOCK);
    ASSERT_NE(c_sock, ASH_INVALID_SOCK);
    uint8_t buf[512], rx[512];
    const auto send_to_server = [&](ash_sock_t s, const ash_rdv1_msg_t &m) {
        size_t len = ash_rdv1_build(buf, sizeof(buf), &m);
        return len > 0u && (int)sendto(s, (const char *)buf, (ash_io_len_t)len, 0, (const struct sockaddr *)&srv_sa, sizeof(srv_sa)) == (int)len;
    };
    const auto receive = [&](ash_sock_t s, ash_rdv1_msg_t *m) {
        int r = (int)recvfrom(s, (char *)rx, (ash_io_len_t)sizeof(rx), 0, nullptr, nullptr);
        return r > 0 && ash_rdv1_parse(rx, (size_t)r, m) ? r : 0;
    };

    ash_rdv1_msg_t reg;
    std::memset(&reg, 0, sizeof(reg));
    reg.type       = ASH_RDV1_REG;
    reg.host_flags = ASH_HF_DTLS_READY | ASH_HF_CAP_OK | ASH_HF_BUSY;
    std::strcpy(reg.name, "presence-host");
    ASSERT_TRUE(send_to_server(h_sock, reg));
    ash_rdv1_msg_t got;
    ASSERT_GT(receive(h_sock, &got), 0);
    ASSERT_EQ(got.type, ASH_RDV1_REG_OK);

    ash_rdv1_msg_t q;
    std::memset(&q, 0, sizeof(q));
    q.type = ASH_RDV1_PRESENCE;
    q.req  = 0x12345678u;
    std::strcpy(q.name, "presence-host");
    const size_t q_len = ash_rdv1_build(buf, sizeof(buf), &q);
    ASSERT_TRUE(send_to_server(c_sock, q));
    const int ok_len = receive(c_sock, &got);
    ASSERT_GT(ok_len, 0);
    EXPECT_EQ(got.type, ASH_RDV1_PRESENCE_OK);
    EXPECT_EQ(got.req, q.req);
    EXPECT_EQ(got.host_flags, reg.host_flags);
    EXPECT_LT((size_t)ok_len, q_len);

    std::strcpy(q.name, "nobody");
    q.req = 0x0BADu;
    ASSERT_TRUE(send_to_server(c_sock, q));
    const int nf_len = receive(c_sock, &got);
    ASSERT_GT(nf_len, 0);
    EXPECT_EQ(got.type, ASH_RDV1_NOTFOUND);
    EXPECT_EQ(got.req, 0x0BADu);

    /* Truncated presence (name length says 5, 1 byte present): no reply */
    const uint8_t broken[] = { ASH_SIG_MAGIC, ASH_RDV1_PRESENCE, 0, 0, 0, 1, 5, 'x' };
    ASSERT_EQ((int)sendto(c_sock, (const char *)broken, (ash_io_len_t)sizeof(broken), 0, (const struct sockaddr *)&srv_sa, sizeof(srv_sa)),
              (int)sizeof(broken));
#ifdef _WIN32
    DWORD short_wait = 300;
    setsockopt(c_sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&short_wait, sizeof(short_wait));
    setsockopt(h_sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&short_wait, sizeof(short_wait));
#else
    struct timeval short_wait = { 0, 300000 };
    setsockopt(c_sock, SOL_SOCKET, SO_RCVTIMEO, &short_wait, sizeof(short_wait));
    setsockopt(h_sock, SOL_SOCKET, SO_RCVTIMEO, &short_wait, sizeof(short_wait));
#endif
    EXPECT_EQ(receive(c_sock, &got), 0);
    /* Presence never reaches the host (no INCOMING, unlike LOOKUP) */
    EXPECT_EQ(receive(h_sock, &got), 0);

    ash_sock_close(c_sock);
    ash_sock_close(h_sock);
    ash_server_destroy(srv);
}

namespace {

struct sockaddr_in loopback_to(uint16_t port) {
    struct sockaddr_in sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port        = htons(port);
    return sa;
}

void set_wait_ms(ash_sock_t s, unsigned ms) {
#ifdef _WIN32
    DWORD tv = ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
#else
    struct timeval tv = { (time_t)(ms / 1000u), (suseconds_t)((ms % 1000u) * 1000u) };
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
}

bool send_v1(ash_sock_t s, const struct sockaddr_in &to, const ash_rdv1_msg_t &m) {
    uint8_t buf[512];
    size_t len = ash_rdv1_build(buf, sizeof(buf), &m);
    return (len > 0u) &&
           ((int)sendto(s, (const char *)buf, (ash_io_len_t)len, 0, (const struct sockaddr *)&to, sizeof(to)) == (int)len);
}

/* Source port of the next datagram that parses as v1; 0 when nothing (parseable) arrives in time */
uint16_t recv_v1(ash_sock_t s, ash_rdv1_msg_t *m) {
    uint8_t rx[512];
    struct sockaddr_in src;
    socklen_t sl = (socklen_t)sizeof(src);
    int r = (int)recvfrom(s, (char *)rx, (ash_io_len_t)sizeof(rx), 0, (struct sockaddr *)&src, &sl);
    return ((r > 0) && ash_rdv1_parse(rx, (size_t)r, m)) ? ntohs(src.sin_port) : 0u;
}

ash_rdv1_msg_t nat_test(uint32_t req, uint32_t sess, uint32_t tok) {
    ash_rdv1_msg_t t;
    std::memset(&t, 0, sizeof(t));
    t.type = ASH_RDV1_NAT_TEST;
    t.req  = req;
    t.sess = sess;
    t.tok  = tok;
    return t;
}

}  // namespace

/* NAT test as AshDesk's adrd_rdv answers it: NAT_OK on the port the test came to; a probe-port test carrying a live
 * session's token also tells the other side the tester's two mappings, from the main port. */
TEST_F(ServerEnv, V1NatTestAnswersOnBothPortsAndTellsTheOtherSide) {
    ash_server_cfg_t cfg;
    ash_server_cfg_defaults(&cfg);
    cfg.bind_ip  = "127.0.0.1";
    cfg.udp_port = 0u;
    ash_server_t *srv = ash_server_create(&cfg);
    ASSERT_NE(srv, nullptr);
    ASSERT_TRUE(ash_server_start(srv));
    const uint16_t main_port  = ash_server_udp_port(srv);
    const uint16_t probe_port = ash_server_probe_port(srv);
    ASSERT_NE(probe_port, 0u);
    const struct sockaddr_in main_sa  = loopback_to(main_port);
    const struct sockaddr_in probe_sa = loopback_to(probe_port);

    /* A second socket per side stands in for the other mapping a NAT gives packets to the probe port */
    uint16_t h_port = 0u, h_alt_port = 0u, c_port = 0u, c_alt_port = 0u;
    ash_sock_t h_sock = open_blocking_udp(&h_port);
    ash_sock_t h_alt  = open_blocking_udp(&h_alt_port);
    ash_sock_t c_sock = open_blocking_udp(&c_port);
    ash_sock_t c_alt  = open_blocking_udp(&c_alt_port);
    ASSERT_NE(h_sock, ASH_INVALID_SOCK);
    ASSERT_NE(h_alt, ASH_INVALID_SOCK);
    ASSERT_NE(c_sock, ASH_INVALID_SOCK);
    ASSERT_NE(c_alt, ASH_INVALID_SOCK);

    ash_rdv1_msg_t m, got;
    std::memset(&m, 0, sizeof(m));
    m.type = ASH_RDV1_REG;
    std::strcpy(m.name, "nat-host");
    ASSERT_TRUE(send_v1(h_sock, main_sa, m));
    ASSERT_EQ(recv_v1(h_sock, &got), main_port);
    ASSERT_EQ(got.type, ASH_RDV1_REG_OK);
    std::memset(&m, 0, sizeof(m));
    m.type = ASH_RDV1_LOOKUP;
    m.req  = 7u;
    std::strcpy(m.name, "nat-host");
    ASSERT_TRUE(send_v1(c_sock, main_sa, m));
    ash_rdv1_msg_t conn, inc;
    ASSERT_EQ(recv_v1(c_sock, &conn), main_port);
    ASSERT_EQ(conn.type, ASH_RDV1_CONN);
    ASSERT_EQ(recv_v1(h_sock, &inc), main_port);
    ASSERT_EQ(inc.type, ASH_RDV1_INCOMING);
    ASSERT_EQ(inc.sess, conn.sess);

    /* Host's probe-port test: NAT_OK back on the probe port, NAT_PEER to the client from the main port */
    ASSERT_TRUE(send_v1(h_alt, probe_sa, nat_test(2u, inc.sess, inc.tok)));
    ASSERT_EQ(recv_v1(h_alt, &got), probe_port);
    EXPECT_EQ(got.type, ASH_RDV1_NAT_OK);
    EXPECT_EQ(got.req, 2u);
    ASSERT_EQ(got.ncand, 1u);
    EXPECT_EQ(got.cand[0].port, h_alt_port);
    ASSERT_EQ(recv_v1(c_sock, &got), main_port);
    EXPECT_EQ(got.type, ASH_RDV1_NAT_PEER);
    EXPECT_EQ(got.sess, inc.sess);
    ASSERT_EQ(got.ncand, 2u);
    EXPECT_EQ(got.cand[0].port, h_port);
    EXPECT_EQ(got.cand[1].port, h_alt_port);

    /* The client's test reaches the host the same way */
    ASSERT_TRUE(send_v1(c_alt, probe_sa, nat_test(2u, conn.sess, conn.tok)));
    ASSERT_EQ(recv_v1(c_alt, &got), probe_port);
    EXPECT_EQ(got.type, ASH_RDV1_NAT_OK);
    EXPECT_EQ(got.cand[0].port, c_alt_port);
    ASSERT_EQ(recv_v1(h_sock, &got), main_port);
    EXPECT_EQ(got.type, ASH_RDV1_NAT_PEER);
    ASSERT_EQ(got.ncand, 2u);
    EXPECT_EQ(got.cand[0].port, c_port);
    EXPECT_EQ(got.cand[1].port, c_alt_port);

    /* Main-port test: NAT_OK from the main port, and no NAT_PEER */
    ASSERT_TRUE(send_v1(h_sock, main_sa, nat_test(1u, inc.sess, inc.tok)));
    ASSERT_EQ(recv_v1(h_sock, &got), main_port);
    EXPECT_EQ(got.type, ASH_RDV1_NAT_OK);
    EXPECT_EQ(got.req, 1u);
    EXPECT_EQ(got.cand[0].port, h_port);
    set_wait_ms(c_sock, 300u);
    set_wait_ms(h_sock, 300u);
    EXPECT_EQ(recv_v1(c_sock, &got), 0u);

    /* Probe-port tests that prove nothing about a session (foreign token, no session, unknown session): NAT_OK only */
    const uint32_t foreign[3][2] = { { inc.sess, inc.tok ^ 1u }, { 0u, 0u }, { inc.sess ^ 0x40u, inc.tok } };
    for (const auto &st : foreign) {
        ASSERT_TRUE(send_v1(h_alt, probe_sa, nat_test(2u, st[0], st[1])));
        ASSERT_EQ(recv_v1(h_alt, &got), probe_port);
        EXPECT_EQ(got.type, ASH_RDV1_NAT_OK);
        EXPECT_EQ(recv_v1(c_sock, &got), 0u);
        EXPECT_EQ(recv_v1(h_sock, &got), 0u);
    }

    ash_sock_close(c_alt);
    ash_sock_close(c_sock);
    ash_sock_close(h_alt);
    ash_sock_close(h_sock);
    ash_server_destroy(srv);
}

/* Well-formed v1 the server answers or ignores is never a strike (AshDesk sends a NAT test every punch round); bytes
 * that do not parse still are, and 16 of them block the source, signaling included. */
TEST_F(ServerEnv, V1RepliesAndNatTestsAreNotStrikesButGarbageStillIs) {
    ash_server_cfg_t cfg;
    ash_server_cfg_defaults(&cfg);
    cfg.bind_ip  = "127.0.0.1";
    cfg.udp_port = 0u;
    ash_server_t *srv = ash_server_create(&cfg);
    ASSERT_NE(srv, nullptr);
    ASSERT_TRUE(ash_server_start(srv));
    const struct sockaddr_in main_sa = loopback_to(ash_server_udp_port(srv));
    ash_sock_t c_sock = open_blocking_udp(nullptr);
    ASSERT_NE(c_sock, ASH_INVALID_SOCK);

    ash_rdv1_msg_t got;
    const auto still_served = [&]() {
        ash_rdv1_msg_t q;
        std::memset(&q, 0, sizeof(q));
        q.type = ASH_RDV1_PRESENCE;
        q.req  = 0xBEEFu;
        std::strcpy(q.name, "nobody");
        if (!send_v1(c_sock, main_sa, q)) return false;
        while (recv_v1(c_sock, &got) != 0u) {
            if ((got.type == ASH_RDV1_NOTFOUND) && (got.req == q.req)) return true;
        }
        return false;
    };

    /* More NAT tests than the 16-strike limit: every one answered, source still served */
    for (int i = 0; i < 20; ++i) ASSERT_TRUE(send_v1(c_sock, main_sa, nat_test(1u, 0u, 0u)));
    int answered = 0;
    while ((answered < 20) && (recv_v1(c_sock, &got) != 0u) && (got.type == ASH_RDV1_NAT_OK)) ++answered;
    EXPECT_EQ(answered, 20);
    EXPECT_TRUE(still_served());

    /* Reply types echoed back at the server: ignored, not strikes */
    ash_rdv1_msg_t echo;
    std::memset(&echo, 0, sizeof(echo));
    echo.type  = ASH_RDV1_REG_OK;
    echo.ncand = 1u;
    ASSERT_TRUE(ash_ep_parse("127.0.0.1:9", 0u, &echo.cand[0]));
    for (int i = 0; i < 20; ++i) ASSERT_TRUE(send_v1(c_sock, main_sa, echo));
    EXPECT_TRUE(still_served());

    /* Truncated NAT tests do not parse: the 16th strike blocks 127.0.0.1, so even a valid query goes unanswered */
    const uint8_t cut[] = { ASH_SIG_MAGIC, ASH_RDV1_NAT_TEST, 0, 0, 0, 1 };
    for (int i = 0; i < 20; ++i) {
        ASSERT_EQ((int)sendto(c_sock, (const char *)cut, (ash_io_len_t)sizeof(cut), 0, (const struct sockaddr *)&main_sa,
                              sizeof(main_sa)),
                  (int)sizeof(cut));
    }
    set_wait_ms(c_sock, 300u);
    EXPECT_FALSE(still_served());

    ash_sock_close(c_sock);
    ash_server_destroy(srv);
}

/* AshDesk number ownership over the wire (docs/号码连接设计.md §4.2), as AshDesk's adrd_rdv does it: a plain REG for a
 * 9-digit name is answered with REG_CHAL; the signed REG registers; keepalives need no proof; a second key gets
 * REG_TAKEN; a replayed proof from another address only earns a fresh challenge; LOOKUP and PRESENCE see the host. */
TEST_F(ServerEnv, V1NumberIsProvedWithASignedRegistrationAndASecondKeyIsTurnedAway) {
    ash_server_cfg_t cfg;
    ash_server_cfg_defaults(&cfg);
    cfg.bind_ip  = "127.0.0.1";
    cfg.udp_port = 0u;
    cfg.ip_new_numbers_per_day = 2u;  /* All sockets below are one source (127.0.0.1) */
    ash_server_t *srv = ash_server_create(&cfg);
    ASSERT_NE(srv, nullptr);
    ASSERT_TRUE(ash_server_start(srv));
    const struct sockaddr_in main_sa = loopback_to(ash_server_udp_port(srv));
    uint16_t host_port = 0u;
    ash_sock_t host   = open_blocking_udp(&host_port);
    ash_sock_t thief  = open_blocking_udp(nullptr);
    ash_sock_t client = open_blocking_udp(nullptr);
    ASSERT_NE(host, ASH_INVALID_SOCK);
    ASSERT_NE(thief, ASH_INVALID_SOCK);
    ASSERT_NE(client, ASH_INVALID_SOCK);

    uint8_t seed_a[32], pub_a[32], sec_a[64];
    uint8_t seed_b[32], pub_b[32], sec_b[64];
    std::memset(seed_a, 0x11, sizeof(seed_a));
    std::memset(seed_b, 0x22, sizeof(seed_b));
    ash_ed25519_keypair(seed_a, pub_a, sec_a);
    ash_ed25519_keypair(seed_b, pub_b, sec_b);

    ash_rdv1_msg_t plain, got;
    std::memset(&plain, 0, sizeof(plain));
    plain.type       = ASH_RDV1_REG;
    plain.host_flags = ASH_HF_DTLS_READY | ASH_HF_PASSWORD;
    std::strcpy(plain.name, "300000001");

    /* 1. Plain REG: challenged, not registered */
    ASSERT_TRUE(send_v1(host, main_sa, plain));
    ASSERT_NE(recv_v1(host, &got), 0u);
    ASSERT_EQ(got.type, ASH_RDV1_REG_CHAL);

    /* 2. Signed REG: registered at the address the server saw */
    ash_rdv1_msg_t proof = plain;
    ASSERT_TRUE(ash_rdv1_own_sign(&proof, got.own_nonce, pub_a, sec_a));
    ASSERT_TRUE(send_v1(host, main_sa, proof));
    ASSERT_NE(recv_v1(host, &got), 0u);
    ASSERT_EQ(got.type, ASH_RDV1_REG_OK);
    ASSERT_EQ(got.ncand, 1u);
    EXPECT_EQ(got.cand[0].port, host_port);

    /* 3. Keepalive without proof */
    ASSERT_TRUE(send_v1(host, main_sa, plain));
    ASSERT_NE(recv_v1(host, &got), 0u);
    EXPECT_EQ(got.type, ASH_RDV1_REG_OK);

    /* 4. Another machine, another key: challenged like anyone, then turned away by name */
    ASSERT_TRUE(send_v1(thief, main_sa, plain));
    ASSERT_NE(recv_v1(thief, &got), 0u);
    ASSERT_EQ(got.type, ASH_RDV1_REG_CHAL);
    ash_rdv1_msg_t theft = plain;
    ASSERT_TRUE(ash_rdv1_own_sign(&theft, got.own_nonce, pub_b, sec_b));
    ASSERT_TRUE(send_v1(thief, main_sa, theft));
    ASSERT_NE(recv_v1(thief, &got), 0u);
    EXPECT_EQ(got.type, ASH_RDV1_REG_TAKEN);
    EXPECT_STREQ(got.name, "300000001");

    /* 5. The owner's proof replayed from the thief's address: its nonce was issued elsewhere */
    ASSERT_TRUE(send_v1(thief, main_sa, proof));
    ASSERT_NE(recv_v1(thief, &got), 0u);
    EXPECT_EQ(got.type, ASH_RDV1_REG_CHAL);

    /* 6. The number still resolves to the owner; AshDesk's "accepts passwords" flag (0x10) passes through */
    ash_rdv1_msg_t query;
    std::memset(&query, 0, sizeof(query));
    query.type = ASH_RDV1_PRESENCE;
    query.req  = 0x0A0Bu;
    std::strcpy(query.name, "300000001");
    ASSERT_TRUE(send_v1(client, main_sa, query));
    ASSERT_NE(recv_v1(client, &got), 0u);
    ASSERT_EQ(got.type, ASH_RDV1_PRESENCE_OK);
    EXPECT_EQ(got.host_flags, ASH_HF_DTLS_READY | ASH_HF_PASSWORD);
    query.type = ASH_RDV1_LOOKUP;
    query.req  = 0x0C0Du;
    ASSERT_TRUE(send_v1(client, main_sa, query));
    ASSERT_NE(recv_v1(client, &got), 0u);
    ASSERT_EQ(got.type, ASH_RDV1_CONN);
    ASSERT_GE(got.ncand, 1u);
    EXPECT_EQ(got.cand[0].port, host_port);
    EXPECT_EQ(got.host_flags, ASH_HF_DTLS_READY | ASH_HF_PASSWORD);
    ASSERT_NE(recv_v1(host, &got), 0u);
    EXPECT_EQ(got.type, ASH_RDV1_INCOMING);

    /* 7. A right nonce with a broken signature is a strike, and a plain name still registers without any of this */
    ASSERT_TRUE(send_v1(thief, main_sa, plain));
    ASSERT_NE(recv_v1(thief, &got), 0u);
    ASSERT_EQ(got.type, ASH_RDV1_REG_CHAL);
    theft = plain;
    ASSERT_TRUE(ash_rdv1_own_sign(&theft, got.own_nonce, pub_b, sec_b));
    theft.own_sig[0] ^= 1u;
    ASSERT_TRUE(send_v1(thief, main_sa, theft));
    set_wait_ms(thief, 300u);
    EXPECT_EQ(recv_v1(thief, &got), 0u);
    ash_rdv1_msg_t named = plain;
    std::strcpy(named.name, "office-pc");
    ASSERT_TRUE(send_v1(client, main_sa, named));
    ASSERT_NE(recv_v1(client, &got), 0u);
    EXPECT_EQ(got.type, ASH_RDV1_REG_OK);

    /* 8. This source may claim two new numbers a day: the second one registers, the third gets no answer; the
     * number it already owns still proves and registers from a new socket */
    const auto claim = [&](ash_sock_t sock, const char *number, const uint8_t *pub, const uint8_t *sec) {
        ash_rdv1_msg_t m = plain;
        std::strcpy(m.name, number);
        if (!send_v1(sock, main_sa, m) || (recv_v1(sock, &got) == 0u) || (got.type != ASH_RDV1_REG_CHAL)) return 0;
        if (!ash_rdv1_own_sign(&m, got.own_nonce, pub, sec) || !send_v1(sock, main_sa, m)) return 0;
        return (recv_v1(sock, &got) != 0u) ? (int)got.type : -1;
    };
    EXPECT_EQ(claim(thief, "300000002", pub_b, sec_b), (int)ASH_RDV1_REG_OK);
    EXPECT_EQ(claim(thief, "300000003", pub_b, sec_b), -1);
    ash_sock_t moved = open_blocking_udp(nullptr);
    ASSERT_NE(moved, ASH_INVALID_SOCK);
    EXPECT_EQ(claim(moved, "300000001", pub_a, sec_a), (int)ASH_RDV1_REG_OK);
    ash_sock_close(moved);

    ash_sock_close(host);
    ash_sock_close(thief);
    ash_sock_close(client);
    ash_server_destroy(srv);
}

/* TCP 443 leg of a v1 relay session (AshDesk --rdv-tcp): a keyframe-sized burst from the UDP host must reach a client that is
 * not reading yet, because the relay cannot slow a UDP sender down and the TCP leg's kernel buffer has to hold it. Far beyond
 * the buffer whole frames are dropped, and the stream stays correctly framed and in order. */
TEST_F(ServerEnv, V1TcpLegAbsorbsAKeyframeBurstAndDropsWholeFramesBeyondIt) {
    ash_server_cfg_t cfg;
    ash_server_cfg_defaults(&cfg);
    cfg.bind_ip  = "127.0.0.1";
    cfg.udp_port = 0u;
    cfg.tcp_port = 65535u;   /* ephemeral TCP port */
    ash_server_t *srv = ash_server_create(&cfg);
    ASSERT_NE(srv, nullptr);
    ASSERT_TRUE(ash_server_start(srv));
    const struct sockaddr_in main_sa = loopback_to(ash_server_udp_port(srv));

    ash_sock_t h_sock = open_blocking_udp(nullptr);
    ASSERT_NE(h_sock, ASH_INVALID_SOCK);
    ash_rdv1_msg_t m, got;
    std::memset(&m, 0, sizeof(m));
    m.type = ASH_RDV1_REG;
    std::strcpy(m.name, "tcp-host");
    ASSERT_TRUE(send_v1(h_sock, main_sa, m));
    ASSERT_NE(recv_v1(h_sock, &got), 0u);

    /* A small receive window, so the server's send buffer is what has to hold the burst */
    ash_sock_t c_tcp = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ASSERT_NE(c_tcp, ASH_INVALID_SOCK);
    int rcvbuf = 16 * 1024;
    setsockopt(c_tcp, SOL_SOCKET, SO_RCVBUF, (const char *)&rcvbuf, sizeof(rcvbuf));
    set_wait_ms(c_tcp, 1000u);
    const struct sockaddr_in tcp_sa = loopback_to(ash_server_tcp_port(srv));
    ASSERT_EQ(connect(c_tcp, (const struct sockaddr *)&tcp_sa, sizeof(tcp_sa)), 0);
    const auto send_frame = [&](const uint8_t *p, size_t n) {
        uint8_t f[2u + 512u];
        f[0] = (uint8_t)(n >> 8u);
        f[1] = (uint8_t)(n & 0xFFu);
        std::memcpy(f + 2, p, n);
        return send_all_tcp(c_tcp, f, n + 2u);
    };
    const auto recv_frame = [&](uint8_t *p, size_t cap) -> size_t {
        uint8_t hl[2];
        if (!recv_exact_tcp(c_tcp, hl, 2u)) return 0u;
        const size_t n = ((size_t)hl[0] << 8u) | hl[1];
        return ((n > 0u) && (n <= cap) && recv_exact_tcp(c_tcp, p, n)) ? n : 0u;
    };

    std::memset(&m, 0, sizeof(m));
    m.type = ASH_RDV1_LOOKUP;
    m.req  = 9u;
    std::strcpy(m.name, "tcp-host");
    uint8_t buf[2048];
    size_t n = ash_rdv1_build(buf, sizeof(buf), &m);
    ASSERT_TRUE(send_frame(buf, n));
    ash_rdv1_msg_t conn, inc;
    n = recv_frame(buf, sizeof(buf));
    ASSERT_TRUE((n > 0u) && ash_rdv1_parse(buf, n, &conn));
    ASSERT_EQ(conn.type, ASH_RDV1_CONN);
    ASSERT_NE(recv_v1(h_sock, &inc), 0u);
    ASSERT_EQ(inc.type, ASH_RDV1_INCOMING);

    /* Host sends `count` relay packets of 1200 B (sequence number first) as fast as it can; the client reads only afterwards */
    uint32_t seq = 0u;
    const auto burst_then_read = [&](uint32_t count, uint32_t *got_frames, bool *in_order) {
        uint8_t payload[1200];
        std::memset(payload, 0x5A, sizeof(payload));
        for (uint32_t i = 0u; i < count; ++i) {
            ++seq;
            std::memcpy(payload, &seq, sizeof(seq));
            size_t pl = ash_relay_wrap(buf, sizeof(buf), inc.sess, inc.tok, payload, sizeof(payload));
            (void)sendto(h_sock, (const char *)buf, (ash_io_len_t)pl, 0, (const struct sockaddr *)&main_sa, sizeof(main_sa));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        *got_frames = 0u;
        *in_order   = true;
        uint32_t last = 0u;
        for (size_t fl; (fl = recv_frame(buf, sizeof(buf))) > 0u;) {
            uint32_t s = 0u;
            if ((fl != ASH_RELAY_HDR_BYTES + sizeof(payload)) || (ash_relay_unwrap(buf, fl, nullptr, nullptr) == 0u)) {
                *in_order = false;
                break;
            }
            std::memcpy(&s, buf + ASH_RELAY_HDR_BYTES, sizeof(s));
            if (s <= last) *in_order = false;
            last = s;
            ++*got_frames;
        }
    };

    uint32_t frames = 0u;
    bool ordered = false;
    burst_then_read(256u, &frames, &ordered);   /* ~310 KB, a 1080p keyframe */
    EXPECT_EQ(frames, 256u);
    EXPECT_TRUE(ordered);
    burst_then_read(6000u, &frames, &ordered);  /* ~7 MB: more than the buffers hold */
    EXPECT_GT(frames, 0u);
    EXPECT_LT(frames, 6000u);
    EXPECT_TRUE(ordered);

    ash_sock_close(c_tcp);
    ash_sock_close(h_sock);
    ash_server_destroy(srv);
}

TEST_F(ServerEnv, DistributedIdAndRelayClusterPlusTcp443FirewallBridgeAndMetrics) {
    uint8_t cluster_secret[32], license_secret[32];
    std::memset(cluster_secret, 0xAB, sizeof(cluster_secret));
    std::memset(license_secret, 0xCD, sizeof(license_secret));

    /* 1. Start standalone ID / Rendezvous Server (with strict cookie challenge + /metrics) */
    ash_server_cfg_t id_cfg;
    ash_server_cfg_defaults(&id_cfg);
    id_cfg.mode          = ASH_MODE_ID;
    id_cfg.bind_ip       = "127.0.0.1";
    id_cfg.udp_port      = 0u;
    id_cfg.metrics_port  = 65535u;
    id_cfg.cookie_policy = ASH_COOKIE_ALWAYS;
    std::memcpy(id_cfg.cluster_secret, cluster_secret, 32u);
    std::memcpy(id_cfg.license_secret, license_secret, 32u);

    ash_server_t *id_srv = ash_server_create(&id_cfg);
    ASSERT_NE(id_srv, nullptr);
    ASSERT_TRUE(ash_server_start(id_srv));

    /* 2. Start standalone Edge Relay Server (UDP + TCP 443 fallback) reporting heartbeats to ID Server */
    ash_server_cfg_t rl_cfg;
    ash_server_cfg_defaults(&rl_cfg);
    rl_cfg.mode          = ASH_MODE_RELAY;
    rl_cfg.bind_ip       = "127.0.0.1";
    rl_cfg.udp_port      = 0u;
    rl_cfg.tcp_port      = 65535u;
    rl_cfg.node_id       = 77u;
    rl_cfg.node_tier_max = ASH_TIER_VIP;
    std::memcpy(rl_cfg.cluster_secret, cluster_secret, 32u);
    rl_cfg.upstream_id_ep.fam   = 4u;
    rl_cfg.upstream_id_ep.proto = 17u;
    rl_cfg.upstream_id_ep.port  = ash_server_udp_port(id_srv);
    rl_cfg.upstream_id_ep.ip[0] = 127u; rl_cfg.upstream_id_ep.ip[3] = 1u;

    /* Set public loopback IP; ports will be filled automatically from bound ports in heartbeat */
    rl_cfg.public_udp_ep.fam = 4u; rl_cfg.public_udp_ep.proto = 17u;
    rl_cfg.public_udp_ep.ip[0] = 127u; rl_cfg.public_udp_ep.ip[3] = 1u;
    rl_cfg.public_tcp_ep.fam = 4u; rl_cfg.public_tcp_ep.proto = 6u;
    rl_cfg.public_tcp_ep.ip[0] = 127u; rl_cfg.public_tcp_ep.ip[3] = 1u;

    ash_server_t *rl_srv = ash_server_create(&rl_cfg);
    ASSERT_NE(rl_srv, nullptr);
    ASSERT_TRUE(ash_server_start(rl_srv));

    /* Wait up to 300 ms for Edge Relay Node heartbeat to register on ID Server */
    char mtext[2048];
    for (int w = 0; w < 15; ++w) {
        ash_server_format_metrics(id_srv, mtext, sizeof(mtext));
        if (std::strstr(mtext, "ash_healthy_relay_nodes 1") != nullptr) break;
        ash_sleep_ms(30u);
    }
    ash_server_format_metrics(id_srv, mtext, sizeof(mtext));
    EXPECT_NE(std::strstr(mtext, "ash_healthy_relay_nodes 1"), nullptr);

    struct sockaddr_in id_sa, rl_sa;
    std::memset(&id_sa, 0, sizeof(id_sa));
    id_sa.sin_family = AF_INET; id_sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    id_sa.sin_port = htons(ash_server_udp_port(id_srv));

    std::memset(&rl_sa, 0, sizeof(rl_sa));
    rl_sa.sin_family = AF_INET; rl_sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    rl_sa.sin_port = htons(ash_server_udp_port(rl_srv));

    /* 3. Host authenticates with Ed25519 over UDP (including Stateless Cookie Challenge!) */
    ash_sock_t h_udp = open_blocking_udp(nullptr);
    ASSERT_NE(h_udp, ASH_INVALID_SOCK);

    uint8_t seed[32], pub[32], sec[64];
    std::memset(seed, 0x24, sizeof(seed));
    ash_ed25519_keypair(seed, pub, sec);

    ash_msg_reg_v2_t reg2;
    std::memset(&reg2, 0, sizeof(reg2));
    reg2.host_flags = ASH_HF_DTLS_READY | ASH_HF_CAP_OK;
    reg2.ts_ms      = ash_wall_ms();
    std::strcpy(reg2.name, "corp-render-01");
    ash_reg_v2_sign(&reg2, sec);

    uint8_t pkt[512], rx[512];
    size_t n = ash_build_reg_v2(pkt, sizeof(pkt), &reg2);
    ASSERT_EQ((int)sendto(h_udp, (const char *)pkt, (ash_io_len_t)n, 0,
                          (const struct sockaddr *)&id_sa, sizeof(id_sa)), (int)n);

    /* First attempt without cookie receives ASH_MSG_COOKIE_CHALLENGE */
    int r = (int)recvfrom(h_udp, (char *)rx, (ash_io_len_t)sizeof(rx), 0, nullptr, nullptr);
    ASSERT_GT(r, 0);
    ash_msg_challenge_t ch;
    ASSERT_TRUE(ash_parse_challenge(rx, (size_t)r, &ch));

    /* Re-sign with stateless cookie -> ASH_STATUS_OK */
    std::memcpy(reg2.cookie, ch.cookie, ASH_COOKIE_LEN);
    reg2.ts_ms += 1ULL;
    ash_reg_v2_sign(&reg2, sec);
    n = ash_build_reg_v2(pkt, sizeof(pkt), &reg2);
    ASSERT_EQ((int)sendto(h_udp, (const char *)pkt, (ash_io_len_t)n, 0,
                          (const struct sockaddr *)&id_sa, sizeof(id_sa)), (int)n);

    r = (int)recvfrom(h_udp, (char *)rx, (ash_io_len_t)sizeof(rx), 0, nullptr, nullptr);
    ASSERT_GT(r, 0);
    ash_msg_reg_ok_v2_t reg_ok;
    ASSERT_TRUE(ash_parse_reg_ok_v2(rx, (size_t)r, &reg_ok));
    EXPECT_EQ(reg_ok.status, ASH_STATUS_OK);

    /* 4. Client with VIP License looks up Host and gets routed to Edge Relay Server! */
    ash_sock_t c_udp_sig = open_blocking_udp(nullptr);
    ASSERT_NE(c_udp_sig, ASH_INVALID_SOCK);

    ash_license_claims_t vip_claims;
    vip_claims.tier         = ASH_TIER_VIP;
    vip_claims.pool_id      = 0u;
    vip_claims.max_kbps     = 88000u;
    vip_claims.expire_ms    = 0ULL;
    vip_claims.subject_hash = 0u;

    ash_msg_lookup_v2_t lk2;
    std::memset(&lk2, 0, sizeof(lk2));
    lk2.prefer_tcp  = 1u; /* Corporate firewall blocks media UDP */
    lk2.req         = 0x77889900u;
    std::strcpy(lk2.name, "corp-render-01");
    lk2.has_license = true;
    ash_license_sign(license_secret, &vip_claims, lk2.license);

    n = ash_build_lookup_v2(pkt, sizeof(pkt), &lk2);
    ASSERT_EQ((int)sendto(c_udp_sig, (const char *)pkt, (ash_io_len_t)n, 0,
                          (const struct sockaddr *)&id_sa, sizeof(id_sa)), (int)n);
    r = (int)recvfrom(c_udp_sig, (char *)rx, (ash_io_len_t)sizeof(rx), 0, nullptr, nullptr);
    ASSERT_TRUE(ash_parse_challenge(rx, (size_t)r, &ch));

    std::memcpy(lk2.cookie, ch.cookie, ASH_COOKIE_LEN);
    n = ash_build_lookup_v2(pkt, sizeof(pkt), &lk2);
    ASSERT_EQ((int)sendto(c_udp_sig, (const char *)pkt, (ash_io_len_t)n, 0,
                          (const struct sockaddr *)&id_sa, sizeof(id_sa)), (int)n);

    r = (int)recvfrom(c_udp_sig, (char *)rx, (ash_io_len_t)sizeof(rx), 0, nullptr, nullptr);
    ASSERT_GT(r, 0);
    ash_msg_conn_v2_t conn_c;
    ASSERT_TRUE(ash_parse_conn_v2(rx, (size_t)r, &conn_c));
    EXPECT_EQ(conn_c.tier, ASH_TIER_VIP);
    EXPECT_EQ(conn_c.relay_max_kbps, 88000u);
    EXPECT_EQ(conn_c.relay_udp.port, ash_server_udp_port(rl_srv));
    EXPECT_EQ(conn_c.relay_tcp.port, ash_server_tcp_port(rl_srv));

    r = (int)recvfrom(h_udp, (char *)rx, (ash_io_len_t)sizeof(rx), 0, nullptr, nullptr);
    ASSERT_GT(r, 0);
    ash_msg_conn_v2_t inc_h;
    ASSERT_TRUE(ash_parse_conn_v2(rx, (size_t)r, &inc_h));
    EXPECT_EQ(inc_h.sess, conn_c.sess);

    /* 5. Client connects to Edge Relay's TCP 443 fallback using TLS 0x17 Camouflage Framing,
     *    while Host stays on UDP -> Heterogeneous TCP <-> UDP Bridge! */
    ash_sock_t c_tcp = connect_blocking_tcp(conn_c.relay_tcp.port);
    ASSERT_NE(c_tcp, ASH_INVALID_SOCK);

    ash_msg_relay_bind_t bind_c;
    bind_c.role = 2u;
    std::memcpy(bind_c.ticket, conn_c.relay_ticket, ASH_TICKET_BYTES);
    uint8_t raw_bind[64], tls_frame[256];
    size_t blen = ash_build_relay_bind(raw_bind, sizeof(raw_bind), &bind_c);
    size_t tlen = ash_tcp_frame_encode(ASH_TCP_FRAME_TLS_APP, raw_bind, blen, tls_frame, sizeof(tls_frame));
    ASSERT_TRUE(send_all_tcp(c_tcp, tls_frame, tlen));

    /* Receive TLS-framed ASH_MSG_RELAY_BIND_OK (5B TLS header + 15B payload) */
    uint8_t tls_rx[128];
    ASSERT_TRUE(recv_exact_tcp(c_tcp, tls_rx, 5u + 15u));
    EXPECT_EQ(tls_rx[0], 0x17u);
    ash_msg_relay_bind_ok_t bind_ok;
    ASSERT_TRUE(ash_parse_relay_bind_ok(tls_rx + 5u, 15u, &bind_ok));
    EXPECT_EQ(bind_ok.status, ASH_STATUS_OK);
    EXPECT_EQ(bind_ok.max_kbps, 88000u);

    /* Host sends UDP Relay packet -> Client receives TLS-framed TCP packet! */
    const char *video_slice = "ULRD-H264-KEYFRAME-SLICE-OVER-UDP-TO-TCP443";
    size_t vlen = ash_relay_wrap(pkt, sizeof(pkt), inc_h.sess, inc_h.tok,
                                 (const uint8_t *)video_slice, std::strlen(video_slice));
    ASSERT_EQ((int)sendto(h_udp, (const char *)pkt, (ash_io_len_t)vlen, 0,
                          (const struct sockaddr *)&rl_sa, sizeof(rl_sa)), (int)vlen);

    ASSERT_TRUE(recv_exact_tcp(c_tcp, tls_rx, 5u + vlen));
    uint32_t out_sess = 0u, out_tok = 99u;
    size_t out_pl = ash_relay_unwrap(tls_rx + 5u, vlen, &out_sess, &out_tok);
    EXPECT_EQ(out_sess, conn_c.sess);
    EXPECT_EQ(out_tok, 0u);
    EXPECT_EQ(std::memcmp(tls_rx + 5u + ASH_RELAY_HDR_BYTES, video_slice, out_pl), 0);

    /* Client sends TLS-framed TCP control packet -> Host receives raw UDP Relay packet! */
    const char *mouse_ev = "ADRD-MOUSE-MOVE-OVER-TCP443-TO-UDP";
    size_t clen = ash_relay_wrap(pkt, sizeof(pkt), conn_c.sess, conn_c.tok,
                                 (const uint8_t *)mouse_ev, std::strlen(mouse_ev));
    tlen = ash_tcp_frame_encode(ASH_TCP_FRAME_TLS_APP, pkt, clen, tls_frame, sizeof(tls_frame));
    ASSERT_TRUE(send_all_tcp(c_tcp, tls_frame, tlen));

    r = (int)recvfrom(h_udp, (char *)rx, (ash_io_len_t)sizeof(rx), 0, nullptr, nullptr);
    ASSERT_EQ(r, (int)clen);
    out_pl = ash_relay_unwrap(rx, (size_t)r, &out_sess, &out_tok);
    EXPECT_EQ(out_tok, 0u);
    EXPECT_EQ(std::memcmp(rx + ASH_RELAY_HDR_BYTES, mouse_ev, out_pl), 0);

    /* 6. Verify HTTP /healthz endpoint on ID Server */
    ash_sock_t m_tcp = connect_blocking_tcp(ash_server_metrics_port(id_srv));
    ASSERT_NE(m_tcp, ASH_INVALID_SOCK);
    const char *hreq = "GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n";
    ASSERT_TRUE(send_all_tcp(m_tcp, (const uint8_t *)hreq, std::strlen(hreq)));
    char hresp[512] = {};
#ifdef _WIN32
    int hr = recv(m_tcp, hresp, sizeof(hresp) - 1, 0);
#else
    int hr = (int)recv(m_tcp, hresp, sizeof(hresp) - 1, 0);
#endif
    ASSERT_GT(hr, 0);
    EXPECT_NE(std::strstr(hresp, "200 OK"), nullptr);
    EXPECT_NE(std::strstr(hresp, "\"status\":\"ok\""), nullptr);

    ash_sock_close(m_tcp);
    ash_sock_close(c_tcp);
    ash_sock_close(c_udp_sig);
    ash_sock_close(h_udp);
    ash_server_destroy(rl_srv);
    ash_server_destroy(id_srv);
}
