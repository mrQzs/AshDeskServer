#include "ash_server.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#endif

static ash_atomic_u64 g_stop_flag;

#ifdef _WIN32
static BOOL WINAPI on_ctrl_handler(DWORD ctrl_type) {
    (void)ctrl_type;
    ash_atomic_store(&g_stop_flag, 1ULL);
    return TRUE;
}
#else
static void on_sig_stop(int sig) {
    (void)sig;
    ash_atomic_store(&g_stop_flag, 1ULL);
}
#endif

static void install_signal_handlers(void) {
    ash_atomic_init(&g_stop_flag, 0ULL);
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCtrlHandler(on_ctrl_handler, TRUE);
#else
    signal(SIGINT, on_sig_stop);
    signal(SIGTERM, on_sig_stop);
#endif
}

static bool parse_u32_strict(const char *s, uint32_t *out) {
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

static bool load_hex_key_file(const char *path, uint8_t out_key[32]) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) return false;
    char hex[128];
    size_t n = fread(hex, 1u, sizeof(hex) - 1u, f);
    fclose(f);
    while ((n > 0u) && ((hex[n - 1u] == '\n') || (hex[n - 1u] == '\r') || (hex[n - 1u] == ' '))) {
        n -= 1u;
    }
    hex[n] = '\0';
    return ash_hex_decode(hex, out_key, 32u);
}

static void print_usage(void) {
    fprintf(stderr,
        "用法: ash_server [选项]\n"
        "  --mode all|id|relay          运行形态：合一 / 仅信令注册 / 仅中继转发（默认 all）\n"
        "  --bind <IP>                  绑定地址（默认 :: 双栈）\n"
        "  --port <N>                   主 UDP 端口（默认 %u）\n"
        "  --tcp-port <N>               TCP 443 防火墙穿透回退端口（默认 0 关闭，建议 443）\n"
        "  --metrics-port <N>           Prometheus /metrics 与 /healthz 端口（默认 127.0.0.1）\n"
        "  --workers <N>                工作线程数（Linux SO_REUSEPORT，0=自动）\n"
        "  --max-hosts <N>              最大在线设备槽位（默认 65536）\n"
        "  --max-sessions <N>           最大并发中继会话（默认 65536）\n"
        "  --max-tcp-conns <N>          最大并发 TCP 连接（默认 4096）\n"
        "  --strict-v2                  强制 Ed25519 v2 鉴权，拒绝未签名的 v1 注册\n"
        "  --limit-new-numbers <N>      一个来源 IP 一天最多新占几个 AshDesk 号码（默认 300，0 = 不限）\n"
        "  --cookie adaptive|always|off UDP 源地址无状态 Cookie 策略（默认 adaptive）\n"
        "  --keystore <文件>            设备 Ed25519 公钥防抢注持久化文件路径\n"
        "  --cluster-key <64位HEX>      集群 HMAC 主密钥（ID 与 Relay 节点共享）\n"
        "  --cluster-key-file <文件>    从文件读取 64 位十六进制集群主密钥\n"
        "  --license-key <64位HEX>      商业授权 Token 验签密钥\n"
        "  --license-key-file <文件>    从文件读取商业授权验签密钥\n"
        "  --free-bw-kbps <K>           免费通道单会话限速 kbps（兼容 --session-bw-kbps）\n"
        "  --pro-bw-kbps <K>            付费高速通道单会话限速 kbps（默认 20000）\n"
        "  --vip-bw-kbps <K>            VIP 极速通道单会话限速 kbps（默认 100000）\n"
        "  --free-pool-kbps <K>         免费池总带宽上限 kbps（保障付费通道带宽隔离）\n"
        "  --total-bw-kbps <K>          本节点总转发带宽上限 kbps（0=不限）\n"
        "  --node-id <N>                分布式中继节点编号\n"
        "  --pool-id <N>                专享节点池 ID（0=公共共享池，>0=企业专享节点）\n"
        "  --public-udp <IP:Port>       中继节点对外宣告的公网 UDP 地址\n"
        "  --public-tcp <IP:Port>       中继节点对外宣告的公网 TCP 443 地址\n"
        "  --id-server <IP:Port>        独立 Relay 节点上报心跳的信令服务器地址\n"
        "  --stats-interval <秒>        控制台统计输出周期（默认 10，0=关闭）\n",
        (unsigned)ASH_DEFAULT_UDP_PORT
    );
}

static bool parse_cli(int argc, char **argv, ash_server_cfg_t *cfg, uint32_t *out_stats_sec) {
    *out_stats_sec = 10u;
    for (int i = 1; i < argc; ++i) {
        const char *a = argv[i];
        const char *v = ((i + 1) < argc) ? argv[i + 1] : NULL;

        if (strcmp(a, "--strict-v2") == 0) {
            cfg->allow_v1_unauth = false;
            continue;
        }
        if ((strcmp(a, "--help") == 0) || (strcmp(a, "-h") == 0)) {
            return false;
        }
        if (v == NULL) return false;
        ++i;

        uint32_t u = 0u;
        if (strcmp(a, "--mode") == 0) {
            if (strcmp(v, "all") == 0) cfg->mode = ASH_MODE_ALL;
            else if (strcmp(v, "id") == 0) cfg->mode = ASH_MODE_ID;
            else if (strcmp(v, "relay") == 0) cfg->mode = ASH_MODE_RELAY;
            else return false;
        } else if (strcmp(a, "--bind") == 0) {
            cfg->bind_ip = v;
        } else if (strcmp(a, "--port") == 0) {
            if (!parse_u32_strict(v, &u) || (u > 65535u)) return false;
            cfg->udp_port = (uint16_t)u;
        } else if (strcmp(a, "--tcp-port") == 0) {
            if (!parse_u32_strict(v, &u) || (u > 65535u)) return false;
            cfg->tcp_port = (uint16_t)u;
        } else if (strcmp(a, "--metrics-port") == 0) {
            if (!parse_u32_strict(v, &u) || (u > 65535u)) return false;
            cfg->metrics_port = (uint16_t)u;
        } else if (strcmp(a, "--metrics-bind") == 0) {
            cfg->metrics_bind_ip = v;
        } else if (strcmp(a, "--workers") == 0) {
            if (!parse_u32_strict(v, &cfg->num_workers)) return false;
        } else if (strcmp(a, "--max-hosts") == 0) {
            if (!parse_u32_strict(v, &cfg->max_hosts) || (cfg->max_hosts == 0u)) return false;
        } else if (strcmp(a, "--max-sessions") == 0) {
            if (!parse_u32_strict(v, &cfg->max_sessions) || (cfg->max_sessions == 0u)) return false;
        } else if (strcmp(a, "--max-tcp-conns") == 0) {
            if (!parse_u32_strict(v, &cfg->max_tcp_conns) || (cfg->max_tcp_conns == 0u)) return false;
        } else if (strcmp(a, "--limit-new-numbers") == 0) {
            uint32_t per_day = 0u;
            if (!parse_u32_strict(v, &per_day) || (per_day > 65535u)) return false;
            cfg->ip_new_numbers_per_day = (uint16_t)per_day;
        } else if (strcmp(a, "--cookie") == 0) {
            if (strcmp(v, "adaptive") == 0) cfg->cookie_policy = ASH_COOKIE_ADAPTIVE;
            else if (strcmp(v, "always") == 0) cfg->cookie_policy = ASH_COOKIE_ALWAYS;
            else if (strcmp(v, "off") == 0) cfg->cookie_policy = ASH_COOKIE_OFF;
            else return false;
        } else if (strcmp(a, "--keystore") == 0) {
            cfg->keystore_path = v;
        } else if (strcmp(a, "--cluster-key") == 0) {
            if (!ash_hex_decode(v, cfg->cluster_secret, 32u)) return false;
        } else if (strcmp(a, "--cluster-key-file") == 0) {
            if (!load_hex_key_file(v, cfg->cluster_secret)) return false;
        } else if (strcmp(a, "--license-key") == 0) {
            if (!ash_hex_decode(v, cfg->license_secret, 32u)) return false;
        } else if (strcmp(a, "--license-key-file") == 0) {
            if (!load_hex_key_file(v, cfg->license_secret)) return false;
        } else if ((strcmp(a, "--free-bw-kbps") == 0) || (strcmp(a, "--session-bw-kbps") == 0)) {
            if (!parse_u32_strict(v, &cfg->free_kbps)) return false;
        } else if (strcmp(a, "--pro-bw-kbps") == 0) {
            if (!parse_u32_strict(v, &cfg->pro_kbps)) return false;
        } else if (strcmp(a, "--vip-bw-kbps") == 0) {
            if (!parse_u32_strict(v, &cfg->vip_kbps)) return false;
        } else if (strcmp(a, "--free-pool-kbps") == 0) {
            if (!parse_u32_strict(v, &cfg->free_pool_kbps)) return false;
        } else if (strcmp(a, "--total-bw-kbps") == 0) {
            if (!parse_u32_strict(v, &cfg->total_bw_kbps)) return false;
        } else if (strcmp(a, "--node-id") == 0) {
            if (!parse_u32_strict(v, &cfg->node_id)) return false;
        } else if (strcmp(a, "--pool-id") == 0) {
            if (!parse_u32_strict(v, &u) || (u > 65535u)) return false;
            cfg->node_pool_id = (uint16_t)u;
        } else if (strcmp(a, "--public-udp") == 0) {
            if (!ash_ep_parse(v, ASH_DEFAULT_UDP_PORT, &cfg->public_udp_ep)) return false;
            cfg->public_udp_ep.proto = 17u;
        } else if (strcmp(a, "--public-tcp") == 0) {
            if (!ash_ep_parse(v, ASH_DEFAULT_TCP_PORT, &cfg->public_tcp_ep)) return false;
            cfg->public_tcp_ep.proto = 6u;
        } else if (strcmp(a, "--id-server") == 0) {
            if (!ash_ep_parse(v, ASH_DEFAULT_UDP_PORT, &cfg->upstream_id_ep)) return false;
            cfg->upstream_id_ep.proto = 17u;
        } else if (strcmp(a, "--stats-interval") == 0) {
            if (!parse_u32_strict(v, out_stats_sec)) return false;
        } else {
            return false;
        }
    }
    return true;
}

int main(int argc, char **argv) {
    install_signal_handlers();
    setvbuf(stdout, NULL, _IONBF, 0);

    if (!ash_net_init()) {
        fprintf(stderr, "网络子系统初始化失败\n");
        return 1;
    }

    ash_server_cfg_t cfg;
    ash_server_cfg_defaults(&cfg);
    uint32_t stats_sec = 10u;
    if (!parse_cli(argc, argv, &cfg, &stats_sec)) {
        print_usage();
        ash_net_cleanup();
        return 2;
    }

    ash_server_t *srv = ash_server_create(&cfg);
    if ((srv == NULL) || !ash_server_start(srv)) {
        fprintf(stderr, "AshDeskServer 启动失败（请检查端口 %u / TCP %u 是否被占用或权限不足）\n",
                (unsigned)cfg.udp_port, (unsigned)cfg.tcp_port);
        ash_server_destroy(srv);
        ash_net_cleanup();
        return 1;
    }

    const char *mode_name = (cfg.mode == ASH_MODE_ID) ? "ID/信令服务"
                          : (cfg.mode == ASH_MODE_RELAY) ? "Relay/中继服务"
                          : "All-in-One 信令+中继";
    printf("AshDeskServer 已启动 [%s]：UDP=%u（探测=%u） TCP=%u Metrics=%u 预分配表内存=%.2f MB\n",
           mode_name,
           (unsigned)ash_server_udp_port(srv),
           (unsigned)ash_server_probe_port(srv),
           (unsigned)ash_server_tcp_port(srv),
           (unsigned)ash_server_metrics_port(srv),
           (double)ash_server_allocated_bytes(srv) / (1024.0 * 1024.0));

    uint64_t last_print_us = ash_now_us();
    while (ash_atomic_load(&g_stop_flag) == 0ULL) {
        ash_sleep_ms(100u);
        uint64_t now_us = ash_now_us();
        if ((stats_sec > 0u) && ((now_us - last_print_us) >= ((uint64_t)stats_sec * 1000000ULL))) {
            last_print_us = now_us;
            double rss_mb = (double)ash_rss_bytes() / (1024.0 * 1024.0);
            printf("[运行统计] RSS=%.2f MB CPU=%.2f s\n", rss_mb, ash_cpu_seconds());
        }
    }

    printf("收到退出信号，正在优雅关闭...\n");
    ash_server_destroy(srv);
    ash_net_cleanup();
    return 0;
}
