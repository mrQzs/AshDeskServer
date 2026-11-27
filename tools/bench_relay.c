#include "ash_server.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <poll.h>
#endif

static int cmp_u64(const void *a, const void *b) {
    uint64_t va = *(const uint64_t *)a;
    uint64_t vb = *(const uint64_t *)b;
    return (va < vb) ? -1 : (va > vb) ? 1 : 0;
}

static bool wait_readable(ash_sock_t s, uint32_t timeout_ms) {
#ifdef _WIN32
    WSAPOLLFD pfd;
    pfd.fd      = s;
    pfd.events  = POLLRDNORM;
    pfd.revents = 0;
    return WSAPoll(&pfd, 1u, (INT)timeout_ms) > 0;
#else
    struct pollfd pfd;
    pfd.fd      = s;
    pfd.events  = POLLIN;
    pfd.revents = 0;
    return poll(&pfd, 1u, (int)timeout_ms) > 0;
#endif
}

static bool recv_udp_with_timeout(ash_sock_t s, uint8_t *buf, size_t cap,
                                  uint32_t timeout_ms, size_t *out_len) {
    uint64_t deadline = ash_now_us() + ((uint64_t)timeout_ms * 1000ULL);
    for (;;) {
        struct sockaddr_storage ss;
        socklen_t sl = (socklen_t)sizeof(ss);
        int r = (int)recvfrom(s, (char *)buf, (ash_io_len_t)cap, 0, (struct sockaddr *)&ss, &sl);
        if (r > 0) {
            *out_len = (size_t)r;
            return true;
        }
        uint64_t now = ash_now_us();
        if (now >= deadline) return false;
        uint32_t rem_ms = (uint32_t)((deadline - now + 999ULL) / 1000ULL);
        (void)wait_readable(s, (rem_ms > 20u) ? 20u : rem_ms);
    }
}

int main(int argc, char **argv) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    setvbuf(stdout, NULL, _IONBF, 0);

    uint32_t num_hosts   = 1000u;
    uint32_t relay_pkts  = 50000u;
    size_t   payload_len = 1200u;

    for (int i = 1; i < argc; ++i) {
        if ((strcmp(argv[i], "--hosts") == 0) && ((i + 1) < argc)) {
            num_hosts = (uint32_t)strtoul(argv[++i], NULL, 10);
        } else if ((strcmp(argv[i], "--packets") == 0) && ((i + 1) < argc)) {
            relay_pkts = (uint32_t)strtoul(argv[++i], NULL, 10);
        }
    }

    if (!ash_net_init()) return 1;

    ash_server_cfg_t cfg;
    ash_server_cfg_defaults(&cfg);
    cfg.bind_ip        = "127.0.0.1";
    cfg.udp_port       = 0u;
    cfg.tcp_port       = 65535u;
    cfg.cookie_policy  = ASH_COOKIE_OFF;
    cfg.ip_sig_rps     = 65000u;
    cfg.max_hosts      = 65536u;
    cfg.max_sessions   = 65536u;
    cfg.max_tcp_conns  = 4096u;

    ash_server_t *srv = ash_server_create(&cfg);
    if ((srv == NULL) || !ash_server_start(srv)) {
        fprintf(stderr, "ash_bench: 服务端启动失败\n");
        ash_server_destroy(srv);
        ash_net_cleanup();
        return 1;
    }

    ash_ep_t srv_ep;
    memset(&srv_ep, 0, sizeof(srv_ep));
    srv_ep.fam   = 4u;
    srv_ep.proto = 17u;
    srv_ep.port  = ash_server_udp_port(srv);
    srv_ep.ip[0] = 127u; srv_ep.ip[3] = 1u;

    struct sockaddr_in6 srv_sa6;
    socklen_t srv_salen = ash_ep_to_sockaddr6(&srv_ep, &srv_sa6);

    /* 1. Benchmark Ed25519 Signed Device Registration (Direct Registry API + Real Socket) */
    uint8_t seed[32], pub[32], sec[64];
    (void)ash_csprng(seed, sizeof(seed));
    ash_ed25519_keypair(seed, pub, sec);

    ash_sock_t sock_h = ash_udp_bind("127.0.0.1", 0u, false, 8 * 1024 * 1024);
    ash_sock_t sock_c = ash_udp_bind("127.0.0.1", 0u, false, 8 * 1024 * 1024);
    if ((sock_h == ASH_INVALID_SOCK) || (sock_c == ASH_INVALID_SOCK)) {
        ash_sock_close(sock_h);
        ash_sock_close(sock_c);
        ash_server_destroy(srv);
        ash_net_cleanup();
        return 1;
    }

    /* Pre-sign host registration packets so benchmark measures pure server throughput, not client signing */
    uint8_t (*reg_pkts)[256] = (uint8_t (*)[256])calloc(num_hosts, 256u);
    size_t  *reg_lens        = (size_t *)calloc(num_hosts, sizeof(size_t));
    if ((reg_pkts == NULL) || (reg_lens == NULL)) {
        free(reg_pkts);
        free(reg_lens);
        ash_sock_close(sock_h);
        ash_sock_close(sock_c);
        ash_server_destroy(srv);
        ash_net_cleanup();
        return 1;
    }
    for (uint32_t i = 0u; i < num_hosts; ++i) {
        ash_msg_reg_v2_t reg;
        memset(&reg, 0, sizeof(reg));
        reg.host_flags = ASH_HF_DTLS_READY | ASH_HF_CAP_OK;
        reg.ts_ms      = ash_wall_ms() + i;
        snprintf(reg.name, sizeof(reg.name), "bench-host-%u", (unsigned)i);
        ash_reg_v2_sign(&reg, sec);
        reg_lens[i] = ash_build_reg_v2(reg_pkts[i], 256u, &reg);
    }

    uint64_t t_reg0 = ash_now_us();
    uint32_t reg_acked = 0u;
    uint32_t sent_idx  = 0u;
    uint8_t  rbuf[128];
    uint64_t reg_deadline = t_reg0 + 10000000ULL;
    while ((reg_acked < num_hosts) && (ash_now_us() < reg_deadline)) {
        /* Keep up to 128 registrations in flight so UDP buffer never overflows */
        while ((sent_idx < num_hosts) && ((sent_idx - reg_acked) < 128u)) {
            (void)sendto(sock_h, (const char *)reg_pkts[sent_idx], (ash_io_len_t)reg_lens[sent_idx], 0,
                         (const struct sockaddr *)&srv_sa6, srv_salen);
            sent_idx += 1u;
        }
        bool any = false;
        for (int drain = 0; drain < 32; ++drain) {
            struct sockaddr_storage ss;
            socklen_t sl = (socklen_t)sizeof(ss);
            if (recvfrom(sock_h, (char *)rbuf, (ash_io_len_t)sizeof(rbuf), 0, (struct sockaddr *)&ss, &sl) <= 0) {
                break;
            }
            reg_acked += 1u;
            any = true;
        }
        if (!any) (void)wait_readable(sock_h, 5u);
    }
    uint64_t t_reg1 = ash_now_us();
    double reg_sec  = (double)(t_reg1 - t_reg0) / 1e6;
    free(reg_pkts);
    free(reg_lens);

    /* 2. Establish 1 session via LOOKUP_V2 and measure P50/P99 One-Way Relay Latency (1000 samples) */
    ash_msg_lookup_v2_t lk;
    memset(&lk, 0, sizeof(lk));
    lk.req = 0x12345678u;
    snprintf(lk.name, sizeof(lk.name), "bench-host-0");
    uint8_t lkpkt[256], rsp[512];
    size_t lkn = ash_build_lookup_v2(lkpkt, sizeof(lkpkt), &lk);
    (void)sendto(sock_c, (const char *)lkpkt, (ash_io_len_t)lkn, 0,
                 (const struct sockaddr *)&srv_sa6, srv_salen);

    size_t rlen = 0u;
    if (!recv_udp_with_timeout(sock_c, rsp, sizeof(rsp), 1000u, &rlen)) {
        fprintf(stderr, "ash_bench: LOOKUP_V2 超时\n");
        ash_sock_close(sock_h);
        ash_sock_close(sock_c);
        ash_server_destroy(srv);
        ash_net_cleanup();
        return 1;
    }
    ash_msg_conn_v2_t conn_c;
    if (!ash_parse_conn_v2(rsp, rlen, &conn_c)) {
        fprintf(stderr, "ash_bench: CONN_V2 解析失败\n");
        ash_sock_close(sock_h);
        ash_sock_close(sock_c);
        ash_server_destroy(srv);
        ash_net_cleanup();
        return 1;
    }

    /* Drain host socket until INCOMING_V2 arrives to get tok_h */
    uint32_t tok_h = 0u;
    uint64_t wait_dl = ash_now_us() + 1000000ULL;
    while (ash_now_us() < wait_dl) {
        struct sockaddr_storage ss;
        socklen_t sl = (socklen_t)sizeof(ss);
        int r = (int)recvfrom(sock_h, (char *)rsp, (ash_io_len_t)sizeof(rsp), 0, (struct sockaddr *)&ss, &sl);
        if (r <= 0) {
            (void)wait_readable(sock_h, 5u);
            continue;
        }
        ash_msg_conn_v2_t inm;
        if (ash_parse_conn_v2(rsp, (size_t)r, &inm) && (inm.sess == conn_c.sess)) {
            tok_h = inm.tok;
            break;
        }
    }

    /* Prime client endpoint on Relay */
    uint8_t media_in[ASH_RELAY_HDR_BYTES + 1200u];
    uint8_t dummy_pl[1200u];
    memset(dummy_pl, 0xA5, sizeof(dummy_pl));
    size_t rwrap = ash_relay_wrap(media_in, sizeof(media_in), conn_c.sess, conn_c.tok, dummy_pl, 64u);
    (void)sendto(sock_c, (const char *)media_in, (ash_io_len_t)rwrap, 0,
                 (const struct sockaddr *)&srv_sa6, srv_salen);
    (void)recv_udp_with_timeout(sock_h, rsp, sizeof(rsp), 200u, &rlen);

    const size_t lat_n = 500u;
    uint64_t samples[500];
    memset(samples, 0, sizeof(samples));
    size_t got_lat = 0u;
    uint8_t rx_media[1500];
    for (size_t i = 0u; i < lat_n; ++i) {
        uint64_t t0 = ash_now_us();
        ash_put_be64(dummy_pl, t0);
        size_t wn = ash_relay_wrap(media_in, sizeof(media_in), conn_c.sess, tok_h, dummy_pl, payload_len);
        (void)sendto(sock_h, (const char *)media_in, (ash_io_len_t)wn, 0,
                     (const struct sockaddr *)&srv_sa6, srv_salen);
        size_t got = 0u;
        if (recv_udp_with_timeout(sock_c, rx_media, sizeof(rx_media), 100u, &got) &&
            (got == (ASH_RELAY_HDR_BYTES + payload_len))) {
            uint64_t t1 = ash_now_us();
            samples[got_lat++] = (t1 >= t0) ? (t1 - t0) : 0ULL;
        }
    }
    if (got_lat > 1u) {
        qsort(samples, got_lat, sizeof(uint64_t), cmp_u64);
    }
    uint64_t p50_us = (got_lat > 0u) ? samples[got_lat / 2u] : 0ULL;
    uint64_t p99_us = (got_lat > 0u) ? samples[(got_lat * 99u) / 100u] : 0ULL;

    /* 3. Sustained High-Throughput Relay Burst */
    double cpu0   = ash_cpu_seconds();
    uint64_t tb0  = ash_now_us();
    size_t wn     = ash_relay_wrap(media_in, sizeof(media_in), conn_c.sess, tok_h, dummy_pl, payload_len);
    uint32_t rx_cnt = 0u;

    for (uint32_t i = 0u; i < relay_pkts; ++i) {
        (void)sendto(sock_h, (const char *)media_in, (ash_io_len_t)wn, 0,
                     (const struct sockaddr *)&srv_sa6, srv_salen);
        for (int d = 0; d < 4; ++d) {
            struct sockaddr_storage ss;
            socklen_t sl = (socklen_t)sizeof(ss);
            int r = (int)recvfrom(sock_c, (char *)rx_media, (ash_io_len_t)sizeof(rx_media), 0,
                                  (struct sockaddr *)&ss, &sl);
            if (r <= 0) break;
            rx_cnt += 1u;
        }
    }
    uint64_t drain_until = ash_now_us() + 100000ULL;
    while ((rx_cnt < relay_pkts) && (ash_now_us() < drain_until)) {
        struct sockaddr_storage ss;
        socklen_t sl = (socklen_t)sizeof(ss);
        int r = (int)recvfrom(sock_c, (char *)rx_media, (ash_io_len_t)sizeof(rx_media), 0,
                              (struct sockaddr *)&ss, &sl);
        if (r > 0) rx_cnt += 1u;
        else (void)wait_readable(sock_c, 2u);
    }
    uint64_t tb1 = ash_now_us();
    double cpu1  = ash_cpu_seconds();

    double dt_s    = (double)(tb1 - tb0) / 1e6;
    double pps     = (dt_s > 0.0) ? ((double)rx_cnt / dt_s) : 0.0;
    double mbps    = (dt_s > 0.0) ? (((double)rx_cnt * (double)wn * 8.0) / dt_s / 1e6) : 0.0;
    double cpu_pct = (dt_s > 0.0) ? (((cpu1 - cpu0) / dt_s) * 100.0) : 0.0;
    double tbl_mb  = (double)ash_server_allocated_bytes(srv) / (1024.0 * 1024.0);
    double rss_mb  = (double)ash_rss_bytes() / (1024.0 * 1024.0);

    printf("=== AshDeskServer 实测基准报告 ===\n");
    printf("1. Ed25519 设备注册吞吐 : %u 台 / %.3f s (%.0f 次签名验签注册/s)\n",
           (unsigned)num_hosts, reg_sec, (reg_sec > 0.0) ? ((double)num_hosts / reg_sec) : 0.0);
    printf("2. 单跳中继转发延迟     : P50 = %llu us, P99 = %llu us (样本=%zu)\n",
           (unsigned long long)p50_us, (unsigned long long)p99_us, got_lat);
    printf("3. 单核环回转发吞吐     : 收发 %u/%u 包, %.0f pkt/s, %.1f Mbit/s\n",
           (unsigned)rx_cnt, (unsigned)relay_pkts, pps, mbps);
    printf("4. 资源开销 (6.5万槽位) : 预分配表=%.2f MB, 进程总 RSS=%.2f MB, 本进程总 CPU=%.1f%%\n",
           tbl_mb, rss_mb, cpu_pct);

    ash_sock_close(sock_h);
    ash_sock_close(sock_c);
    ash_server_destroy(srv);
    ash_net_cleanup();
    return 0;
}
