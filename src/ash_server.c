#include "ash_server.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#else
#include <errno.h>
#ifdef __linux__
#include <sys/epoll.h>
#else
#include <poll.h>
#endif
#include <sys/socket.h>
#include <unistd.h>
#endif

#define ASH_MAX_WORKERS     32u
#define ASH_UDP_BATCH       ((size_t)64u)
#define ASH_TCP_RX_CAP      4096u
#define ASH_TCP_TX_CAP      8192u
/* Kernel send buffer of a TCP 443 leg. A limit, not a reservation (memory follows what is queued), but it has to hold a
 * keyframe burst from the UDP side: the relay cannot slow a UDP sender down, so what fits neither here nor in the backlog
 * above is dropped. With 64 KB a 1080p session over 443 lost 45 % of its packets (AshDesk test 2026-11-13) */
#define ASH_TCP_SNDBUF      (1024 * 1024)
#define ASH_TCP_IDLE_US     90000000ULL

typedef struct {
    uint8_t rx[ASH_TCP_RX_CAP];
    uint8_t tx[ASH_TCP_TX_CAP];
} ash_tcp_buf_t;

typedef struct {
    ash_mutex_t          mu;
    bool                 used;
    uint32_t             gen;
    ash_sock_t           fd;
    ash_ep_t             peer;
    ash_tcp_frame_mode_t frame_mode;
    uint64_t             conn_id;
    uint64_t             last_rx_us;
    size_t               rx_len;
    size_t               tx_len;
    ash_tcp_buf_t       *buf;
} ash_tcp_slot_t;

typedef struct {
    ash_server_t   *srv;
    uint32_t        worker_id;
    ash_sock_t      udp_fd;
    ash_sock_t      probe_fd;
    ash_sock_t      tcp_listen_fd;
#ifdef __linux__
    int             ep_fd;
#endif
    ash_tcp_slot_t *tcp_slots;
    uint32_t        tcp_cap;
    uint32_t        sweep_idx;
    ash_thread_t    thread;
} ash_worker_t;

struct ash_server_s {
    ash_server_cfg_t  cfg;
    ash_atomic_u64    running;
    uint16_t          bound_udp_port;
    uint16_t          bound_probe_port;
    uint16_t          bound_tcp_port;
    uint16_t          bound_metrics_port;

    bool              has_guard;
    bool              has_cookies;
    bool              has_registry;
    bool              has_relay;
    ash_registry_t    registry;
    ash_relay_table_t relay;
    ash_ip_guard_t    guard;
    ash_cookie_jar_t  cookies;

    ash_atomic_u64    unauth_sig_win_us;
    ash_atomic_u64    unauth_sig_cnt;
    ash_atomic_u64    cookie_until_us;
    ash_atomic_u64    tcp_backpressure_drops;
    ash_atomic_u64    active_tcp_conns;

    uint32_t          num_workers;
    ash_worker_t      workers[ASH_MAX_WORKERS];

    ash_sock_t        metrics_fd;
    ash_thread_t      maint_thread;
    bool              started;
};

void ash_server_cfg_defaults(ash_server_cfg_t *cfg) {
    if (cfg == NULL) return;
    memset(cfg, 0, sizeof(*cfg));
    cfg->mode             = ASH_MODE_ALL;
    cfg->bind_ip          = "::";
    cfg->udp_port         = ASH_DEFAULT_UDP_PORT;
    cfg->enable_nat_probe = true;
    cfg->tcp_port         = 0u;
    cfg->metrics_port     = 0u;
    cfg->metrics_bind_ip  = "127.0.0.1";

    cfg->num_workers      = 0u;
    cfg->max_hosts        = 65536u;
    cfg->max_sessions     = 65536u;
    cfg->max_tcp_conns    = 4096u;

    cfg->allow_v1_unauth  = true;
    cfg->cookie_policy    = ASH_COOKIE_ADAPTIVE;
    cfg->cookie_flood_pps = 500u;
    cfg->ip_sig_rps       = 120u;
    cfg->ip_max_strikes   = 16u;
    cfg->ip_new_numbers_per_day = 300u;

    cfg->host_ttl_sec     = 60ULL;
    cfg->sess_ttl_sec     = 120ULL;
    cfg->keystore_path    = NULL;

    cfg->free_kbps        = 0u; /* 0 = unlimited by default unless operator sets --free-bw-kbps */
    cfg->pro_kbps         = 20000u;
    cfg->vip_kbps         = 100000u;
    cfg->dedicated_kbps   = 0u;
    cfg->free_pool_kbps   = 0u;
    cfg->total_bw_kbps    = 0u;

    cfg->node_id          = 1u;
    cfg->node_tier_max    = (uint8_t)ASH_TIER_VIP;
    cfg->node_pool_id     = 0u;
    cfg->region_id        = 1u;
}

static bool sock_would_block(void) {
#ifdef _WIN32
    int e = WSAGetLastError();
    return (e == WSAEWOULDBLOCK) || (e == WSAEINTR);
#else
    return (errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR);
#endif
}

static int tcp_send_nowait(ash_sock_t fd, const uint8_t *data, size_t len) {
#ifdef _WIN32
    return send(fd, (const char *)data, (int)len, 0);
#elif defined(MSG_NOSIGNAL)
    return (int)send(fd, data, len, MSG_NOSIGNAL);
#else
    return (int)send(fd, data, len, 0);
#endif
}

static int tcp_recv_nowait(ash_sock_t fd, uint8_t *buf, size_t cap) {
#ifdef _WIN32
    return recv(fd, (char *)buf, (int)cap, 0);
#else
    return (int)recv(fd, buf, cap, 0);
#endif
}

static uint64_t make_conn_id(uint32_t gen, uint32_t worker_id, uint32_t slot_idx) {
    uint32_t g = (gen != 0u) ? gen : 1u;
    return (((uint64_t)g) << 32u) | (((uint64_t)(worker_id & 0xFFu)) << 24u) |
           ((uint64_t)(slot_idx & 0xFFFFFFu));
}

static uint64_t tcp_close_slot_locked(ash_server_t *srv, ash_worker_t *w, ash_tcp_slot_t *sl) {
    if (!sl->used) return 0ULL;
    uint64_t cid = sl->conn_id;
#ifdef __linux__
    if (w->ep_fd >= 0) {
        (void)epoll_ctl(w->ep_fd, EPOLL_CTL_DEL, sl->fd, NULL);
    }
#else
    (void)w;
#endif
    ash_sock_close(sl->fd);
    sl->fd       = ASH_INVALID_SOCK;
    sl->used     = false;
    sl->conn_id  = 0ULL;
    sl->rx_len   = 0u;
    sl->tx_len   = 0u;
    if (sl->buf != NULL) {
        free(sl->buf);
        sl->buf = NULL;
    }
    (void)ash_atomic_add(&srv->active_tcp_conns, UINT64_MAX); /* atomic decrement */
    return cid;
}

static void notify_tcp_closed(ash_server_t *srv, uint64_t cid) {
    if (cid == 0ULL) return;
    if (srv->has_registry) ash_registry_on_tcp_closed(&srv->registry, cid);
    if (srv->has_relay)    ash_relay_on_tcp_closed(&srv->relay, cid);
}

static void tcp_update_epoll_events(ash_worker_t *w, ash_tcp_slot_t *sl, uint32_t slot_idx) {
#ifdef __linux__
    if (w->ep_fd < 0) return;
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN | ((sl->tx_len > 0u) ? EPOLLOUT : 0u);
    ev.data.u64 = 0x10000000ULL | (uint64_t)slot_idx;
    (void)epoll_ctl(w->ep_fd, EPOLL_CTL_MOD, sl->fd, &ev);
#else
    (void)w;
    (void)sl;
    (void)slot_idx;
#endif
}

/* Thread-safe framed TCP transmission with strict stream-integrity guarantee */
static bool tcp_send_framed(ash_server_t *srv, uint64_t conn_id,
                            const uint8_t *payload, size_t payload_len) {
    if (conn_id == 0ULL) return false;
    uint32_t wid  = (uint32_t)((conn_id >> 24u) & 0xFFu);
    uint32_t sidx = (uint32_t)(conn_id & 0xFFFFFFu);
    uint32_t gen  = (uint32_t)(conn_id >> 32u);
    if (wid >= srv->num_workers) return false;

    ash_worker_t *w = &srv->workers[wid];
    if (sidx >= w->tcp_cap) return false;
    ash_tcp_slot_t *sl = &w->tcp_slots[sidx];

    uint8_t framed[5u + ASH_MAX_FRAME_PAYLOAD];
    ash_mutex_lock(&sl->mu);
    if (!sl->used || (sl->gen != gen) || (sl->buf == NULL)) {
        ash_mutex_unlock(&sl->mu);
        return false;
    }

    ash_tcp_frame_mode_t mode = (sl->frame_mode == ASH_TCP_FRAME_TLS_APP)
                                ? ASH_TCP_FRAME_TLS_APP
                                : ASH_TCP_FRAME_RFC4571;
    size_t flen = ash_tcp_frame_encode(mode, payload, payload_len, framed, sizeof(framed));
    if (flen == 0u) {
        ash_mutex_unlock(&sl->mu);
        return false;
    }

    /* Case 1: Backlog already pending -> append entire frame atomically or drop cleanly */
    if (sl->tx_len > 0u) {
        if ((sl->tx_len + flen) > ASH_TCP_TX_CAP) {
            ash_mutex_unlock(&sl->mu);
            (void)ash_atomic_inc(&srv->tcp_backpressure_drops);
            return false;
        }
        memcpy(sl->buf->tx + sl->tx_len, framed, flen);
        sl->tx_len += flen;
        ash_mutex_unlock(&sl->mu);
        return true;
    }

    /* Case 2: Empty backlog -> try zero-copy immediate non-blocking send() */
    int sent = tcp_send_nowait(sl->fd, framed, flen);
    if (sent == (int)flen) {
        ash_mutex_unlock(&sl->mu);
        return true;
    }
    if (sent > 0) {
        size_t rem = flen - (size_t)sent;
        memcpy(sl->buf->tx, framed + (size_t)sent, rem);
        sl->tx_len = rem;
        tcp_update_epoll_events(w, sl, sidx);
        ash_mutex_unlock(&sl->mu);
        return true;
    }
    if (sock_would_block()) {
        memcpy(sl->buf->tx, framed, flen);
        sl->tx_len = flen;
        tcp_update_epoll_events(w, sl, sidx);
        ash_mutex_unlock(&sl->mu);
        return true;
    }

    uint64_t closed_cid = tcp_close_slot_locked(srv, w, sl);
    ash_mutex_unlock(&sl->mu);
    notify_tcp_closed(srv, closed_cid);
    return false;
}

static bool tcp_send_raw_bytes(ash_worker_t *w, ash_tcp_slot_t *sl, uint32_t sidx,
                               const uint8_t *raw, size_t len) {
    if ((sl->tx_len == 0u) && (sl->buf != NULL)) {
        int sent = tcp_send_nowait(sl->fd, raw, len);
        if (sent == (int)len) return true;
        if (sent > 0) {
            size_t rem = len - (size_t)sent;
            if (rem <= ASH_TCP_TX_CAP) {
                memcpy(sl->buf->tx, raw + (size_t)sent, rem);
                sl->tx_len = rem;
                tcp_update_epoll_events(w, sl, sidx);
                return true;
            }
            return false;
        }
        if (sock_would_block() && (len <= ASH_TCP_TX_CAP)) {
            memcpy(sl->buf->tx, raw, len);
            sl->tx_len = len;
            tcp_update_epoll_events(w, sl, sidx);
            return true;
        }
        return false;
    }
    if ((sl->buf != NULL) && ((sl->tx_len + len) <= ASH_TCP_TX_CAP)) {
        memcpy(sl->buf->tx + sl->tx_len, raw, len);
        sl->tx_len += len;
        tcp_update_epoll_events(w, sl, sidx);
        return true;
    }
    return false;
}

/* Outbound UDP queue for batched sendmmsg() flushing */
typedef struct {
    struct sockaddr_in6 addrs[ASH_UDP_BATCH * 2u];
    uint8_t             bufs[ASH_UDP_BATCH * 2u][ASH_MAX_FRAME_PAYLOAD];
    size_t              lens[ASH_UDP_BATCH * 2u];
    size_t              count;
} ash_udp_txq_t;

static void udp_txq_flush(ash_sock_t udp_fd, ash_udp_txq_t *txq) {
    if ((txq->count == 0u) || (udp_fd == ASH_INVALID_SOCK)) {
        txq->count = 0u;
        return;
    }
#ifdef __linux__
    struct mmsghdr msgs[ASH_UDP_BATCH * 2u];
    struct iovec   iovs[ASH_UDP_BATCH * 2u];
    memset(msgs, 0, txq->count * sizeof(msgs[0]));
    for (size_t i = 0u; i < txq->count; ++i) {
        iovs[i].iov_base             = txq->bufs[i];
        iovs[i].iov_len              = txq->lens[i];
        msgs[i].msg_hdr.msg_name     = &txq->addrs[i];
        msgs[i].msg_hdr.msg_namelen  = sizeof(struct sockaddr_in6);
        msgs[i].msg_hdr.msg_iov      = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen   = 1u;
    }
    size_t pos = 0u;
    while (pos < txq->count) {
        int sent = sendmmsg(udp_fd, &msgs[pos], (unsigned int)(txq->count - pos), MSG_DONTWAIT);
        if (sent <= 0) break;
        pos += (size_t)sent;
    }
#else
    for (size_t i = 0u; i < txq->count; ++i) {
        (void)sendto(udp_fd, (const char *)txq->bufs[i], (ash_io_len_t)txq->lens[i], 0,
                     (const struct sockaddr *)&txq->addrs[i], (socklen_t)sizeof(struct sockaddr_in6));
    }
#endif
    txq->count = 0u;
}

static void udp_txq_push(ash_sock_t udp_fd, ash_udp_txq_t *txq,
                         const ash_ep_t *dst, const uint8_t *data, size_t len) {
    if ((dst == NULL) || (len == 0u) || (len > ASH_MAX_FRAME_PAYLOAD)) return;
    if (txq->count >= (ASH_UDP_BATCH * 2u)) {
        udp_txq_flush(udp_fd, txq);
    }
    size_t idx = txq->count;
    if (ash_ep_to_sockaddr6(dst, &txq->addrs[idx]) == 0) return;
    memcpy(txq->bufs[idx], data, len);
    txq->lens[idx] = len;
    txq->count     = idx + 1u;
}

static void send_reply(ash_server_t *srv, ash_sock_t udp_fd, ash_udp_txq_t *txq,
                       uint64_t tcp_conn_id, const ash_ep_t *udp_dst,
                       const uint8_t *pkt, size_t len) {
    if (len == 0u) return;
    if (tcp_conn_id != 0ULL) {
        (void)tcp_send_framed(srv, tcp_conn_id, pkt, len);
    } else {
        udp_txq_push(udp_fd, txq, udp_dst, pkt, len);
    }
}

static bool need_udp_cookie(ash_server_t *srv, uint64_t now_us) {
    if (srv->cfg.cookie_policy == ASH_COOKIE_OFF) return false;
    if (srv->cfg.cookie_policy == ASH_COOKIE_ALWAYS) return true;

    uint64_t win = ash_atomic_load(&srv->unauth_sig_win_us);
    if ((now_us < win) || ((now_us - win) >= 1000000ULL)) {
        ash_atomic_store(&srv->unauth_sig_win_us, now_us);
        ash_atomic_store(&srv->unauth_sig_cnt, 1ULL);
    } else {
        uint64_t c = ash_atomic_inc(&srv->unauth_sig_cnt);
        if (c >= (uint64_t)srv->cfg.cookie_flood_pps) {
            ash_atomic_store(&srv->cookie_until_us, now_us + 10000000ULL);
        }
    }
    return now_us < ash_atomic_load(&srv->cookie_until_us);
}

static void resolve_local_relay_eps(const ash_server_t *srv, const ash_ep_t *client_obs,
                                    ash_ep_t *out_udp, ash_ep_t *out_tcp) {
    memset(out_udp, 0, sizeof(*out_udp));
    memset(out_tcp, 0, sizeof(*out_tcp));
    if (srv->cfg.public_udp_ep.fam != 0u) {
        *out_udp = srv->cfg.public_udp_ep;
    } else if ((srv->bound_udp_port != 0u) && (client_obs != NULL) && (client_obs->fam != 0u)) {
        /* If public_udp_ep wasn't explicitly set (e.g. loopback / LAN self-host), reflect loopback/any */
        out_udp->fam   = client_obs->fam;
        out_udp->proto = 17u;
        out_udp->port  = srv->bound_udp_port;
        if (client_obs->fam == 4u) {
            out_udp->ip[0] = 127u; out_udp->ip[3] = 1u;
        } else {
            out_udp->ip[15] = 1u;
        }
    }
    if (srv->cfg.public_tcp_ep.fam != 0u) {
        *out_tcp = srv->cfg.public_tcp_ep;
    } else if ((srv->bound_tcp_port != 0u) && (client_obs != NULL) && (client_obs->fam != 0u)) {
        out_tcp->fam   = client_obs->fam;
        out_tcp->proto = 6u;
        out_tcp->port  = srv->bound_tcp_port;
        if (client_obs->fam == 4u) {
            out_tcp->ip[0] = 127u; out_tcp->ip[3] = 1u;
        } else {
            out_tcp->ip[15] = 1u;
        }
    }
}

/* ---------------- Core Signaling & Relay Packet Dispatcher ---------------- */
static void handle_signaling(ash_server_t *srv, ash_sock_t udp_fd, ash_udp_txq_t *txq,
                             const uint8_t *pkt, size_t len,
                             const ash_ep_t *from, uint64_t tcp_conn_id,
                             uint64_t now_us, uint64_t now_wall_ms) {
    if (len < 2u) return;
    if (!ash_ip_guard_allow_sig(&srv->guard, from, now_us)) return;

    uint8_t mtype = pkt[1];
    uint8_t rsp[512];

    /* 1. Relay Session Ticket Bind (supported on Relay & All-in-One nodes) */
    if (mtype == (uint8_t)ASH_MSG_RELAY_BIND_V2) {
        if (!srv->has_relay) return;
        ash_msg_relay_bind_t bm;
        if (!ash_parse_relay_bind(pkt, len, &bm)) {
            ash_ip_guard_add_strike(&srv->guard, from, now_us);
            return;
        }
        ash_msg_relay_bind_ok_t ok_msg;
        if (!ash_relay_bind_ticket(&srv->relay, &bm, from, tcp_conn_id,
                                   now_us, (uint32_t)(now_wall_ms / 1000ULL), &ok_msg)) {
            ash_ip_guard_add_strike(&srv->guard, from, now_us);
        }
        size_t rl = ash_build_relay_bind_ok(rsp, sizeof(rsp), &ok_msg);
        send_reply(srv, udp_fd, txq, tcp_conn_id, from, rsp, rl);
        return;
    }

    /* All other signaling messages require ID / Rendezvous service */
    if (!srv->has_registry) return;

    /* 2. Distributed Relay Node Cluster Heartbeat */
    if (mtype == (uint8_t)ASH_MSG_NODE_HB) {
        ash_msg_node_hb_t hb;
        if (!ash_parse_node_hb(pkt, len, srv->cfg.cluster_secret, &hb)) {
            ash_ip_guard_add_strike(&srv->guard, from, now_us);
            return;
        }
        ash_registry_upsert_node(&srv->registry, &hb, now_us);
        return;
    }

    /* 3. v1 Compatible Protocol (adp_rdv types 1..13; the requests are REG, LOOKUP, NAT_TEST and PRESENCE) */
    if ((mtype >= (uint8_t)ASH_RDV1_REG) && (mtype <= (uint8_t)ASH_RDV1_REG_TAKEN)) {
        ash_rdv1_msg_t m1;
        if (!ash_rdv1_parse(pkt, len, &m1)) {
            ash_ip_guard_add_strike(&srv->guard, from, now_us);
            return;
        }
        if (m1.type == (uint8_t)ASH_RDV1_NAT_TEST) {
            /* Main-port half of the test; NAT_PEER is only sent for the probe-port half */
            ash_rdv1_msg_t ok;
            memset(&ok, 0, sizeof(ok));
            ok.type    = (uint8_t)ASH_RDV1_NAT_OK;
            ok.req     = m1.req;
            ok.ncand   = 1u;
            ok.cand[0] = *from;
            size_t rl = ash_rdv1_build(rsp, sizeof(rsp), &ok);
            send_reply(srv, udp_fd, txq, tcp_conn_id, from, rsp, rl);
            return;
        }
        if (m1.type == (uint8_t)ASH_RDV1_PRESENCE) {
            /* Online / busy only: no relay session, no INCOMING to the host. Replies are shorter than the request. */
            ash_host_entry_t host;
            ash_rdv1_msg_t pr;
            memset(&pr, 0, sizeof(pr));
            pr.req = m1.req;
            if (ash_registry_lookup_host(&srv->registry, m1.name, now_us, &host)) {
                pr.type       = (uint8_t)ASH_RDV1_PRESENCE_OK;
                pr.host_flags = host.host_flags;
            } else {
                pr.type = (uint8_t)ASH_RDV1_NOTFOUND;
            }
            size_t rl = ash_rdv1_build(rsp, sizeof(rsp), &pr);
            send_reply(srv, udp_fd, txq, tcp_conn_id, from, rsp, rl);
            return;
        }
        if (m1.type == (uint8_t)ASH_RDV1_REG) {
            bool addr_changed = false;
            if (ash_rdv1_number_value(m1.name) != 0u) {
                /* An AshDesk number has to be proved; any other name stays first-come, last-wins */
                ash_rdv1_msg_t ans;
                memset(&ans, 0, sizeof(ans));
                /* A source may claim only so many numbers nobody owns per day; the ones it owns are not counted */
                uint16_t day = (uint16_t)((now_wall_ms / 86400000ULL) & 0xFFFFu);
                bool may_pin = ash_ip_guard_may_pin(&srv->guard, from, now_us, day);
                bool pinned  = false;
                ash_number_result_t nr = ash_registry_on_reg_number(&srv->registry, &m1, from, tcp_conn_id, now_us,
                                                                    may_pin, &addr_changed, &pinned, ans.own_nonce);
                if (pinned) ash_ip_guard_note_pin(&srv->guard, from, now_us, day);
                if (nr == ASH_NUMBER_CHALLENGE) {
                    ans.type = (uint8_t)ASH_RDV1_REG_CHAL;
                } else if (nr == ASH_NUMBER_TAKEN) {
                    ans.type = (uint8_t)ASH_RDV1_REG_TAKEN;
                    memcpy(ans.name, m1.name, sizeof(ans.name));
                } else if (nr != ASH_NUMBER_REGISTERED) {
                    if (nr == ASH_NUMBER_BAD_PROOF) ash_ip_guard_add_strike(&srv->guard, from, now_us);
                    return;
                }
                if (ans.type != 0u) {
                    size_t al = ash_rdv1_build(rsp, sizeof(rsp), &ans);
                    send_reply(srv, udp_fd, txq, tcp_conn_id, from, rsp, al);
                    return;
                }
            } else {
                ash_status_t st = ash_registry_on_reg_v1(&srv->registry, &m1, from, tcp_conn_id,
                                                         now_us, &addr_changed);
                if (st != ASH_STATUS_OK) {
                    if (st == ASH_STATUS_AUTH_FAILED) ash_ip_guard_add_strike(&srv->guard, from, now_us);
                    return;
                }
            }
            if (addr_changed && srv->has_relay) {
                ash_relay_on_host_rebind(&srv->relay, m1.name, from, tcp_conn_id, now_us);
            }
            ash_rdv1_msg_t ok1;
            memset(&ok1, 0, sizeof(ok1));
            ok1.type    = (uint8_t)ASH_RDV1_REG_OK;
            ok1.ncand   = 1u;
            ok1.cand[0] = *from;
            size_t rl = ash_rdv1_build(rsp, sizeof(rsp), &ok1);
            send_reply(srv, udp_fd, txq, tcp_conn_id, from, rsp, rl);
            return;
        }
        /* A well-formed reply type (REG_OK, CONN, NAT_OK, ...) sent to the server: nothing to do, and not a strike */
        if (m1.type != (uint8_t)ASH_RDV1_LOOKUP) return;

        ash_host_entry_t host;
        if (!ash_registry_lookup_host(&srv->registry, m1.name, now_us, &host)) {
            ash_rdv1_msg_t nf;
            memset(&nf, 0, sizeof(nf));
            nf.type = (uint8_t)ASH_RDV1_NOTFOUND;
            nf.req  = m1.req;
            size_t rl = ash_rdv1_build(rsp, sizeof(rsp), &nf);
            send_reply(srv, udp_fd, txq, tcp_conn_id, from, rsp, rl);
            return;
        }

        uint8_t  eff_tier = 0u;
        uint16_t eff_pool = 0u;
        uint32_t eff_kbps = ash_registry_effective_kbps(&srv->registry, &host, NULL,
                                                        &eff_tier, &eff_pool);
        uint32_t now_min  = (uint32_t)(now_wall_ms / 60000ULL);
        uint32_t sess = 0u, tok_h = 0u, tok_c = 0u;

        if (srv->has_relay) {
            if (!ash_relay_create_session(&srv->relay, host.name, m1.req,
                                          &host.obs, host.tcp_conn_id,
                                          from, tcp_conn_id,
                                          eff_tier, eff_pool, eff_kbps,
                                          now_us, now_min,
                                          &sess, &tok_h, &tok_c)) {
                return;
            }
        } else {
            uint32_t seq = (uint32_t)ash_atomic_inc(&srv->unauth_sig_cnt);
            sess = ash_make_sess_id(eff_tier, now_min, seq);
            ash_derive_sess_tokens(srv->cfg.cluster_secret, sess, &tok_h, &tok_c);
        }

        ash_rdv1_msg_t cm;
        memset(&cm, 0, sizeof(cm));
        cm.type           = (uint8_t)ASH_RDV1_CONN;
        cm.req            = m1.req;
        cm.sess           = sess;
        cm.tok            = tok_c;
        cm.host_flags     = host.host_flags;
        cm.relay_max_kbps = eff_kbps;
        cm.cand[cm.ncand++] = host.obs;
        for (uint8_t i = 0u; (i < host.ncand) && (cm.ncand < ASH_MAX_CANDS); ++i) {
            cm.cand[cm.ncand++] = host.cand[i];
        }
        size_t clen = ash_rdv1_build(rsp, sizeof(rsp), &cm);
        send_reply(srv, udp_fd, txq, tcp_conn_id, from, rsp, clen);

        ash_rdv1_msg_t inm;
        memset(&inm, 0, sizeof(inm));
        inm.type           = (uint8_t)ASH_RDV1_INCOMING;
        inm.sess           = sess;
        inm.tok            = tok_h;
        inm.relay_max_kbps = eff_kbps;
        inm.cand[inm.ncand++] = *from;
        for (uint8_t i = 0u; (i < m1.ncand) && (inm.ncand < ASH_MAX_CANDS); ++i) {
            inm.cand[inm.ncand++] = m1.cand[i];
        }
        size_t ilen = ash_rdv1_build(rsp, sizeof(rsp), &inm);
        send_reply(srv, udp_fd, txq, host.tcp_conn_id, &host.obs, rsp, ilen);
        return;
    }

    /* 4. v2 Authenticated Registration (ASH_MSG_REG_V2) */
    if (mtype == (uint8_t)ASH_MSG_REG_V2) {
        ash_msg_reg_v2_t reg2;
        if (!ash_parse_reg_v2(pkt, len, &reg2)) {
            ash_ip_guard_add_strike(&srv->guard, from, now_us);
            return;
        }
        if ((tcp_conn_id == 0ULL) && need_udp_cookie(srv, now_us) &&
            !ash_cookie_check(&srv->cookies, from, now_us, reg2.cookie)) {
            ash_msg_challenge_t ch;
            ch.orig_type = mtype;
            ash_cookie_make(&srv->cookies, from, now_us, ch.cookie);
            size_t rl = ash_build_challenge(rsp, sizeof(rsp), &ch);
            send_reply(srv, udp_fd, txq, 0ULL, from, rsp, rl);
            return;
        }

        uint8_t assigned_tier = 0u;
        ash_status_t st = ash_registry_on_reg_v2(&srv->registry, &reg2, from, tcp_conn_id,
                                                 now_us, now_wall_ms, &assigned_tier);
        if (st == ASH_STATUS_AUTH_FAILED) {
            ash_ip_guard_add_strike(&srv->guard, from, now_us);
        } else if ((st == ASH_STATUS_OK) && srv->has_relay) {
            ash_relay_on_host_rebind(&srv->relay, reg2.name, from, tcp_conn_id, now_us);
        }

        ash_msg_reg_ok_v2_t ok2;
        memset(&ok2, 0, sizeof(ok2));
        ok2.status     = (uint8_t)st;
        ok2.tier       = assigned_tier;
        ok2.probe_port = srv->bound_probe_port;
        ok2.hb_sec     = (uint16_t)((srv->cfg.host_ttl_sec >= 20ULL) ? (srv->cfg.host_ttl_sec / 4ULL) : 5ULL);
        ok2.obs        = *from;
        size_t rl = ash_build_reg_ok_v2(rsp, sizeof(rsp), &ok2);
        send_reply(srv, udp_fd, txq, tcp_conn_id, from, rsp, rl);
        return;
    }

    /* 5. v2 Graceful Unregister (ASH_MSG_UNREG_V2) */
    if (mtype == (uint8_t)ASH_MSG_UNREG_V2) {
        ash_msg_unreg_v2_t unreg;
        if (!ash_parse_unreg_v2(pkt, len, &unreg) ||
            !ash_registry_on_unreg_v2(&srv->registry, &unreg, now_wall_ms)) {
            ash_ip_guard_add_strike(&srv->guard, from, now_us);
        }
        return;
    }

    /* 6. v2 Lookup & Coordinated NAT Traversal + Commercial Relay Allocation */
    if (mtype == (uint8_t)ASH_MSG_LOOKUP_V2) {
        ash_msg_lookup_v2_t lk;
        if (!ash_parse_lookup_v2(pkt, len, &lk)) {
            ash_ip_guard_add_strike(&srv->guard, from, now_us);
            return;
        }
        if ((tcp_conn_id == 0ULL) && need_udp_cookie(srv, now_us) &&
            !ash_cookie_check(&srv->cookies, from, now_us, lk.cookie)) {
            ash_msg_challenge_t ch;
            ch.orig_type = mtype;
            ash_cookie_make(&srv->cookies, from, now_us, ch.cookie);
            size_t rl = ash_build_challenge(rsp, sizeof(rsp), &ch);
            send_reply(srv, udp_fd, txq, 0ULL, from, rsp, rl);
            return;
        }

        ash_license_claims_t cli_lic;
        const ash_license_claims_t *p_cli_lic = NULL;
        if (lk.has_license) {
            if (!ash_license_verify(srv->cfg.license_secret, lk.license, NULL, now_wall_ms, &cli_lic)) {
                ash_ip_guard_add_strike(&srv->guard, from, now_us);
                return;
            }
            p_cli_lic = &cli_lic;
        }

        ash_host_entry_t host;
        if (!ash_registry_lookup_host(&srv->registry, lk.name, now_us, &host)) {
            ash_rdv1_msg_t nf;
            memset(&nf, 0, sizeof(nf));
            nf.type = (uint8_t)ASH_RDV1_NOTFOUND;
            nf.req  = lk.req;
            size_t rl = ash_rdv1_build(rsp, sizeof(rsp), &nf);
            send_reply(srv, udp_fd, txq, tcp_conn_id, from, rsp, rl);
            return;
        }

        uint8_t  eff_tier = 0u;
        uint16_t eff_pool = lk.pool_id;
        uint32_t eff_kbps = ash_registry_effective_kbps(&srv->registry, &host, p_cli_lic,
                                                        &eff_tier, &eff_pool);
        if ((lk.pool_id != 0u) && (eff_pool == 0u)) eff_pool = lk.pool_id;

        bool need_tcp_relay = (lk.prefer_tcp != 0u) || (tcp_conn_id != 0ULL) || (host.tcp_conn_id != 0ULL);
        ash_ep_t relay_udp, relay_tcp;
        if (!ash_registry_select_relay(&srv->registry, eff_tier, eff_pool, need_tcp_relay,
                                       now_us, &relay_udp, &relay_tcp)) {
            resolve_local_relay_eps(srv, from, &relay_udp, &relay_tcp);
        }

        uint32_t now_min = (uint32_t)(now_wall_ms / 60000ULL);
        uint32_t sess = 0u, tok_h = 0u, tok_c = 0u;
        if (srv->has_relay) {
            if (!ash_relay_create_session(&srv->relay, host.name, lk.req,
                                          &host.obs, host.tcp_conn_id,
                                          from, tcp_conn_id,
                                          eff_tier, eff_pool, eff_kbps,
                                          now_us, now_min,
                                          &sess, &tok_h, &tok_c)) {
                return;
            }
        } else {
            uint32_t seq = (uint32_t)ash_atomic_inc(&srv->unauth_sig_cnt);
            sess = ash_make_sess_id(eff_tier, now_min, seq);
            ash_derive_sess_tokens(srv->cfg.cluster_secret, sess, &tok_h, &tok_c);
        }

        ash_ticket_claims_t tc;
        tc.tier      = eff_tier;
        tc.pool_id   = eff_pool;
        tc.sess      = sess;
        tc.max_kbps  = eff_kbps;
        tc.issue_sec = (uint32_t)(now_wall_ms / 1000ULL);
        tc.ttl_sec   = 600u;
        tc.flags     = 0u;
        uint8_t ticket_raw[ASH_TICKET_BYTES];
        ash_ticket_sign(srv->cfg.cluster_secret, &tc, ticket_raw);

        ash_punch_strategy_t strat = ash_decide_punch_strategy(
            &host, from, lk.cand, lk.ncand,
            (tcp_conn_id != 0ULL) ? (uint8_t)ASH_NAT_UDP_BLOCKED : lk.client_nat,
            lk.prefer_tcp != 0u
        );

        ash_msg_conn_v2_t cm;
        memset(&cm, 0, sizeof(cm));
        cm.type           = (uint8_t)ASH_MSG_CONN_V2;
        cm.req            = lk.req;
        cm.sess           = sess;
        cm.tok            = tok_c;
        cm.punch_strategy = (uint8_t)strat;
        cm.punch_sync_ms  = 25u;
        cm.port_stride    = host.port_stride;
        cm.peer_nat       = host.nat_type;
        cm.host_flags     = host.host_flags;
        cm.tier           = eff_tier;
        cm.relay_max_kbps = eff_kbps;
        cm.relay_udp      = relay_udp;
        cm.relay_tcp      = relay_tcp;
        memcpy(cm.relay_ticket, ticket_raw, ASH_TICKET_BYTES);
        cm.cand[cm.ncand++] = host.obs;
        for (uint8_t i = 0u; (i < host.ncand) && (cm.ncand < ASH_MAX_CANDS); ++i) {
            cm.cand[cm.ncand++] = host.cand[i];
        }
        size_t clen = ash_build_conn_v2(rsp, sizeof(rsp), &cm);
        send_reply(srv, udp_fd, txq, tcp_conn_id, from, rsp, clen);

        ash_msg_conn_v2_t inm;
        memset(&inm, 0, sizeof(inm));
        inm.type           = (uint8_t)ASH_MSG_INCOMING_V2;
        inm.req            = 0u;
        inm.sess           = sess;
        inm.tok            = tok_h;
        inm.punch_strategy = (uint8_t)strat;
        inm.punch_sync_ms  = 25u;
        inm.port_stride    = 0;
        inm.peer_nat       = (tcp_conn_id != 0ULL) ? (uint8_t)ASH_NAT_UDP_BLOCKED : lk.client_nat;
        inm.host_flags     = 0u;
        inm.tier           = eff_tier;
        inm.relay_max_kbps = eff_kbps;
        inm.relay_udp      = relay_udp;
        inm.relay_tcp      = relay_tcp;
        memcpy(inm.relay_ticket, ticket_raw, ASH_TICKET_BYTES);
        inm.cand[inm.ncand++] = *from;
        for (uint8_t i = 0u; (i < lk.ncand) && (inm.ncand < ASH_MAX_CANDS); ++i) {
            inm.cand[inm.ncand++] = lk.cand[i];
        }
        size_t ilen = ash_build_conn_v2(rsp, sizeof(rsp), &inm);
        send_reply(srv, udp_fd, txq, host.tcp_conn_id, &host.obs, rsp, ilen);
        return;
    }

    ash_ip_guard_add_strike(&srv->guard, from, now_us);
}

static void dispatch_packet(ash_server_t *srv, ash_sock_t udp_fd, ash_udp_txq_t *txq,
                            uint8_t *pkt, size_t len,
                            const ash_ep_t *from, uint64_t tcp_conn_id,
                            uint64_t now_us, uint64_t now_wall_ms) {
    if (len == 0u) return;

    if (pkt[0] == ASH_RELAY_MAGIC) {
        if (!srv->has_relay) return;
        if (ash_ip_guard_is_blocked(&srv->guard, from, now_us)) return;
        ash_relay_route_t rt = ash_relay_on_packet(&srv->relay, pkt, len, from, tcp_conn_id,
                                                   now_us, (uint32_t)(now_wall_ms / 60000ULL));
        if (rt.kind == ASH_ROUTE_UDP) {
            udp_txq_push(udp_fd, txq, &rt.dst_udp, pkt, len);
        } else if (rt.kind == ASH_ROUTE_TCP) {
            (void)tcp_send_framed(srv, rt.dst_tcp_conn, pkt, len);
        } else if (rt.bad_token) {
            ash_ip_guard_add_strike(&srv->guard, from, now_us);
        }
        return;
    }

    if (pkt[0] == ASH_SIG_MAGIC) {
        handle_signaling(srv, udp_fd, txq, pkt, len, from, tcp_conn_id, now_us, now_wall_ms);
        return;
    }

    ash_ip_guard_add_strike(&srv->guard, from, now_us);
}

/* ---------------- UDP Batch Draining ---------------- */
static void drain_udp_primary(ash_worker_t *w, ash_udp_txq_t *txq) {
    if (w->udp_fd == ASH_INVALID_SOCK) return;
    ash_server_t *srv = w->srv;

#ifdef __linux__
    struct sockaddr_storage addrs[ASH_UDP_BATCH];
    uint8_t                 bufs[ASH_UDP_BATCH][ASH_MAX_FRAME_PAYLOAD];
    struct mmsghdr          msgs[ASH_UDP_BATCH];
    struct iovec            iovs[ASH_UDP_BATCH];

    for (unsigned round = 0u; round < 4u; ++round) {
        memset(msgs, 0, sizeof(msgs));
        for (size_t i = 0u; i < ASH_UDP_BATCH; ++i) {
            iovs[i].iov_base            = bufs[i];
            iovs[i].iov_len             = sizeof(bufs[i]);
            msgs[i].msg_hdr.msg_name    = &addrs[i];
            msgs[i].msg_hdr.msg_namelen = sizeof(addrs[i]);
            msgs[i].msg_hdr.msg_iov     = &iovs[i];
            msgs[i].msg_hdr.msg_iovlen  = 1u;
        }
        int n = recvmmsg(w->udp_fd, msgs, (unsigned int)ASH_UDP_BATCH, MSG_DONTWAIT, NULL);
        if (n <= 0) break;

        uint64_t now_us      = ash_now_us();
        uint64_t now_wall_ms = ash_wall_ms();
        for (int i = 0; i < n; ++i) {
            size_t rlen = (size_t)msgs[i].msg_len;
            ash_ep_t from;
            ash_ep_from_sockaddr(&addrs[i], 17u, &from);
            dispatch_packet(srv, w->udp_fd, txq, bufs[i], rlen, &from, 0ULL, now_us, now_wall_ms);
        }
        udp_txq_flush(w->udp_fd, txq);
        if (n < (int)ASH_UDP_BATCH) break;
    }
#else
    uint8_t buf[ASH_MAX_FRAME_PAYLOAD];
    for (unsigned i = 0u; i < ASH_UDP_BATCH; ++i) {
        struct sockaddr_storage ss;
        socklen_t sl = (socklen_t)sizeof(ss);
        int r = (int)recvfrom(w->udp_fd, (char *)buf, (ash_io_len_t)sizeof(buf), 0,
                              (struct sockaddr *)&ss, &sl);
        if (r <= 0) break;
        uint64_t now_us      = ash_now_us();
        uint64_t now_wall_ms = ash_wall_ms();
        ash_ep_t from;
        ash_ep_from_sockaddr(&ss, 17u, &from);
        dispatch_packet(srv, w->udp_fd, txq, buf, (size_t)r, &from, 0ULL, now_us, now_wall_ms);
    }
    udp_txq_flush(w->udp_fd, txq);
#endif
}

static void drain_udp_probe(ash_worker_t *w, ash_udp_txq_t *txq) {
    if (w->probe_fd == ASH_INVALID_SOCK) return;
    ash_server_t *srv = w->srv;
    uint8_t buf[128];
    uint8_t rsp[64];

    for (unsigned i = 0u; i < 32u; ++i) {
        struct sockaddr_storage ss;
        socklen_t sl = (socklen_t)sizeof(ss);
        int r = (int)recvfrom(w->probe_fd, (char *)buf, (ash_io_len_t)sizeof(buf), 0,
                              (struct sockaddr *)&ss, &sl);
        if (r <= 0) break;
        uint64_t now_us = ash_now_us();
        ash_ep_t from;
        ash_ep_from_sockaddr(&ss, 17u, &from);
        if (!ash_ip_guard_allow_sig(&srv->guard, &from, now_us)) continue;

        uint32_t nonce = 0u;
        ash_rdv1_msg_t m1;
        if (ash_parse_nat_probe(buf, (size_t)r, &nonce)) {
            if (srv->has_registry) {
                ash_registry_on_nat_probe(&srv->registry, &from, now_us);
            }
            size_t rl = ash_build_nat_probe_rsp(rsp, sizeof(rsp), nonce, &from);
            udp_txq_push(w->probe_fd, txq, &from, rsp, rl);
        } else if (srv->has_registry && (buf[0] == ASH_SIG_MAGIC) && (buf[1] == (uint8_t)ASH_RDV1_REG)) {
            /* Also support sending v1 REG to secondary port to inspect NAT mapping */
            ash_registry_on_nat_probe(&srv->registry, &from, now_us);
            ash_rdv1_msg_t ok1;
            memset(&ok1, 0, sizeof(ok1));
            ok1.type    = (uint8_t)ASH_RDV1_REG_OK;
            ok1.ncand   = 1u;
            ok1.cand[0] = from;
            size_t rl = ash_rdv1_build(rsp, sizeof(rsp), &ok1);
            udp_txq_push(w->probe_fd, txq, &from, rsp, rl);
        } else if (srv->has_registry && ash_rdv1_parse(buf, (size_t)r, &m1) &&
                   (m1.type == (uint8_t)ASH_RDV1_NAT_TEST)) {
            ash_rdv1_msg_t ok;
            memset(&ok, 0, sizeof(ok));
            ok.type    = (uint8_t)ASH_RDV1_NAT_OK;
            ok.req     = m1.req;
            ok.ncand   = 1u;
            ok.cand[0] = from;
            size_t rl = ash_rdv1_build(rsp, sizeof(rsp), &ok);
            udp_txq_push(w->probe_fd, txq, &from, rsp, rl);

            ash_ep_t tester_main, peer;
            uint64_t peer_tcp = 0ULL;
            if (srv->has_relay &&
                ash_relay_nat_peer(&srv->relay, m1.sess, m1.tok, now_us, &tester_main, &peer, &peer_tcp)) {
                ash_rdv1_msg_t pm;
                memset(&pm, 0, sizeof(pm));
                pm.type    = (uint8_t)ASH_RDV1_NAT_PEER;
                pm.sess    = m1.sess;
                pm.ncand   = 2u;
                pm.cand[0] = tester_main;
                pm.cand[1] = from;
                size_t pl = ash_rdv1_build(rsp, sizeof(rsp), &pm);
                /* Sent from the main port, not this socket's queue: a port-restricted NAT on the peer only lets in
                 * the address its own packets went to */
                struct sockaddr_in6 sa;
                if (peer_tcp != 0ULL) {
                    (void)tcp_send_framed(srv, peer_tcp, rsp, pl);
                } else if ((pl != 0u) && (ash_ep_to_sockaddr6(&peer, &sa) != 0)) {
                    (void)sendto(w->udp_fd, (const char *)rsp, (ash_io_len_t)pl, 0,
                                 (const struct sockaddr *)&sa, (socklen_t)sizeof(sa));
                }
            }
        }
    }
    udp_txq_flush(w->probe_fd, txq);
}

/* ---------------- TCP 443 Accept & Stream Processing ---------------- */
static void accept_tcp_clients(ash_worker_t *w) {
    if (w->tcp_listen_fd == ASH_INVALID_SOCK) return;
    ash_server_t *srv = w->srv;

    for (unsigned k = 0u; k < 32u; ++k) {
        struct sockaddr_storage ss;
        socklen_t sl = (socklen_t)sizeof(ss);
        ash_sock_t cfd = accept(w->tcp_listen_fd, (struct sockaddr *)&ss, &sl);
        if (cfd == ASH_INVALID_SOCK) break;

        uint64_t now_us = ash_now_us();
        ash_ep_t peer;
        ash_ep_from_sockaddr(&ss, 6u, &peer);

        if (ash_ip_guard_is_blocked(&srv->guard, &peer, now_us) ||
            !ash_tcp_tune_accepted(cfd, ASH_TCP_SNDBUF)) {
            ash_sock_close(cfd);
            continue;
        }

        bool placed = false;
        for (uint32_t i = 0u; i < w->tcp_cap; ++i) {
            ash_tcp_slot_t *slot = &w->tcp_slots[i];
            ash_mutex_lock(&slot->mu);
            if (!slot->used) {
                ash_tcp_buf_t *mem = (ash_tcp_buf_t *)malloc(sizeof(ash_tcp_buf_t));
                if (mem == NULL) {
                    ash_mutex_unlock(&slot->mu);
                    break;
                }
                slot->gen += 1u;
                if (slot->gen == 0u) slot->gen = 1u;
                slot->used       = true;
                slot->fd         = cfd;
                slot->peer       = peer;
                slot->frame_mode = ASH_TCP_FRAME_UNKNOWN;
                slot->conn_id    = make_conn_id(slot->gen, w->worker_id, i);
                slot->last_rx_us = now_us;
                slot->rx_len     = 0u;
                slot->tx_len     = 0u;
                slot->buf        = mem;
#ifdef __linux__
                if (w->ep_fd >= 0) {
                    struct epoll_event ev;
                    memset(&ev, 0, sizeof(ev));
                    ev.events   = EPOLLIN;
                    ev.data.u64 = 0x10000000ULL | (uint64_t)i;
                    (void)epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, cfd, &ev);
                }
#endif
                (void)ash_atomic_inc(&srv->active_tcp_conns);
                placed = true;
                ash_mutex_unlock(&slot->mu);
                break;
            }
            ash_mutex_unlock(&slot->mu);
        }
        if (!placed) {
            ash_sock_close(cfd);
        }
    }
}

static void handle_tcp_slot_io(ash_worker_t *w, uint32_t slot_idx,
                               bool can_read, bool can_write, ash_udp_txq_t *txq) {
    ash_server_t *srv   = w->srv;
    ash_tcp_slot_t *sl  = &w->tcp_slots[slot_idx];

    /* 1. Drain pending outbound TX ring if writable */
    if (can_write) {
        ash_mutex_lock(&sl->mu);
        if (sl->used && (sl->tx_len > 0u) && (sl->buf != NULL)) {
            int sent = tcp_send_nowait(sl->fd, sl->buf->tx, sl->tx_len);
            if (sent > 0) {
                size_t rem = sl->tx_len - (size_t)sent;
                if (rem > 0u) {
                    memmove(sl->buf->tx, sl->buf->tx + (size_t)sent, rem);
                }
                sl->tx_len = rem;
                tcp_update_epoll_events(w, sl, slot_idx);
            } else if (!sock_would_block()) {
                uint64_t closed_cid = tcp_close_slot_locked(srv, w, sl);
                ash_mutex_unlock(&sl->mu);
                notify_tcp_closed(srv, closed_cid);
                return;
            }
        }
        ash_mutex_unlock(&sl->mu);
    }

    if (!can_read) return;

    /* 2. Read stream bytes & extract complete frames (dispatch OUTSIDE slot lock to prevent lock-order inversion!) */
    for (unsigned iter = 0u; iter < 16u; ++iter) {
        uint8_t local_frames[8][ASH_MAX_FRAME_PAYLOAD];
        size_t  local_lens[8];
        size_t  nframes = 0u;
        ash_ep_t peer_ep;
        uint64_t conn_id = 0ULL;
        uint64_t closed_cid = 0ULL;
        bool closed = false;
        bool eof_or_empty = false;

        ash_mutex_lock(&sl->mu);
        if (!sl->used || (sl->buf == NULL)) {
            ash_mutex_unlock(&sl->mu);
            return;
        }
        peer_ep = sl->peer;
        conn_id = sl->conn_id;

        size_t avail = ASH_TCP_RX_CAP - sl->rx_len;
        if (avail == 0u) {
            closed_cid = tcp_close_slot_locked(srv, w, sl);
            ash_mutex_unlock(&sl->mu);
            notify_tcp_closed(srv, closed_cid);
            return;
        }

        int got = tcp_recv_nowait(sl->fd, sl->buf->rx + sl->rx_len, avail);
        if (got == 0) {
            closed_cid = tcp_close_slot_locked(srv, w, sl);
            ash_mutex_unlock(&sl->mu);
            notify_tcp_closed(srv, closed_cid);
            return;
        }
        if (got < 0) {
            if (!sock_would_block()) {
                closed_cid = tcp_close_slot_locked(srv, w, sl);
            }
            ash_mutex_unlock(&sl->mu);
            notify_tcp_closed(srv, closed_cid);
            return;
        }

        sl->rx_len     += (size_t)got;
        sl->last_rx_us  = ash_now_us();
        eof_or_empty    = ((size_t)got < avail);

        size_t consumed_total = 0u;
        while ((nframes < 8u) && (consumed_total < sl->rx_len)) {
            const uint8_t *pl = NULL;
            size_t pl_len = 0u;
            bool need_101 = false;
            int step = ash_tcp_frame_decode(&sl->frame_mode,
                                            sl->buf->rx + consumed_total,
                                            sl->rx_len - consumed_total,
                                            &pl, &pl_len, &need_101);
            if (step < 0) {
                closed_cid = tcp_close_slot_locked(srv, w, sl);
                closed = true;
                break;
            }
            if (step == 0) break;
            consumed_total += (size_t)step;

            if (need_101) {
                static const char k_101[] =
                    "HTTP/1.1 101 Switching Protocols\r\n"
                    "Upgrade: ashdesk-relay/1\r\n"
                    "Connection: Upgrade\r\n\r\n";
                (void)tcp_send_raw_bytes(w, sl, slot_idx, (const uint8_t *)k_101, sizeof(k_101) - 1u);
                continue;
            }
            if ((pl != NULL) && (pl_len > 0u) && (pl_len <= ASH_MAX_FRAME_PAYLOAD)) {
                memcpy(local_frames[nframes], pl, pl_len);
                local_lens[nframes] = pl_len;
                nframes += 1u;
            }
        }

        if (!closed && (sl->buf != NULL) && (consumed_total > 0u)) {
            size_t rem = sl->rx_len - consumed_total;
            if (rem > 0u) {
                memmove(sl->buf->rx, sl->buf->rx + consumed_total, rem);
            }
            sl->rx_len = rem;
        }
        ash_mutex_unlock(&sl->mu);
        notify_tcp_closed(srv, closed_cid);

        if (nframes > 0u) {
            uint64_t now_us      = ash_now_us();
            uint64_t now_wall_ms = ash_wall_ms();
            for (size_t f = 0u; f < nframes; ++f) {
                dispatch_packet(srv, w->udp_fd, txq, local_frames[f], local_lens[f],
                                &peer_ep, conn_id, now_us, now_wall_ms);
            }
            udp_txq_flush(w->udp_fd, txq);
        }

        if (closed || eof_or_empty) break;
    }
}

static void worker_sweep_tcp(ash_worker_t *w, uint64_t now_us) {
    if (w->tcp_cap == 0u) return;
    uint32_t batch = (w->tcp_cap < 16u) ? w->tcp_cap : 16u;
    for (uint32_t k = 0u; k < batch; ++k) {
        uint32_t idx = (w->sweep_idx + k) % w->tcp_cap;
        ash_tcp_slot_t *sl = &w->tcp_slots[idx];
        uint64_t closed_cid = 0ULL;
        ash_mutex_lock(&sl->mu);
        if (sl->used && (now_us > sl->last_rx_us) && ((now_us - sl->last_rx_us) > ASH_TCP_IDLE_US)) {
            closed_cid = tcp_close_slot_locked(w->srv, w, sl);
        }
        ash_mutex_unlock(&sl->mu);
        notify_tcp_closed(w->srv, closed_cid);
    }
    w->sweep_idx = (w->sweep_idx + batch) % w->tcp_cap;
}

/* ---------------- Worker Reactor Thread ---------------- */
static void worker_loop(void *arg) {
    ash_worker_t *w   = (ash_worker_t *)arg;
    ash_server_t *srv = w->srv;

    ash_udp_txq_t *txq = (ash_udp_txq_t *)calloc(1u, sizeof(ash_udp_txq_t));
    if (txq == NULL) return;

    uint64_t last_sweep_us = ash_now_us();

#ifdef __linux__
    struct epoll_event events[128];
    while (ash_atomic_load(&srv->running) != 0ULL) {
        int nfds = epoll_wait(w->ep_fd, events, 128, 25);
        for (int i = 0; i < nfds; ++i) {
            uint64_t tag = events[i].data.u64;
            uint32_t ev  = events[i].events;
            if (tag == 1ULL) {
                drain_udp_primary(w, txq);
            } else if (tag == 2ULL) {
                drain_udp_probe(w, txq);
            } else if (tag == 3ULL) {
                accept_tcp_clients(w);
            } else if ((tag & 0x10000000ULL) != 0ULL) {
                uint32_t sidx = (uint32_t)(tag & 0x0FFFFFFFULL);
                bool rd = (ev & (EPOLLIN | EPOLLERR | EPOLLHUP)) != 0u;
                bool wr = (ev & EPOLLOUT) != 0u;
                handle_tcp_slot_io(w, sidx, rd, wr, txq);
            }
        }
        uint64_t now_us = ash_now_us();
        if ((now_us > last_sweep_us) && ((now_us - last_sweep_us) >= 500000ULL)) {
            worker_sweep_tcp(w, now_us);
            last_sweep_us = now_us;
        }
    }
#else
    uint32_t max_pfds = 3u + w->tcp_cap;
#ifdef _WIN32
    WSAPOLLFD *pfds = (WSAPOLLFD *)calloc(max_pfds, sizeof(WSAPOLLFD));
#else
    struct pollfd *pfds = (struct pollfd *)calloc(max_pfds, sizeof(struct pollfd));
#endif
    uint32_t *pfd_map = (uint32_t *)calloc(max_pfds, sizeof(uint32_t));
    if ((pfds == NULL) || (pfd_map == NULL)) {
        free(pfds);
        free(pfd_map);
        free(txq);
        return;
    }

    while (ash_atomic_load(&srv->running) != 0ULL) {
        uint32_t n = 0u;
        if (w->udp_fd != ASH_INVALID_SOCK) {
            pfds[n].fd = w->udp_fd; pfds[n].events = POLLRDNORM; pfds[n].revents = 0;
            pfd_map[n++] = 0x80000001u;
        }
        if (w->probe_fd != ASH_INVALID_SOCK) {
            pfds[n].fd = w->probe_fd; pfds[n].events = POLLRDNORM; pfds[n].revents = 0;
            pfd_map[n++] = 0x80000002u;
        }
        if (w->tcp_listen_fd != ASH_INVALID_SOCK) {
            pfds[n].fd = w->tcp_listen_fd; pfds[n].events = POLLRDNORM; pfds[n].revents = 0;
            pfd_map[n++] = 0x80000003u;
        }
        for (uint32_t i = 0u; i < w->tcp_cap; ++i) {
            ash_tcp_slot_t *sl = &w->tcp_slots[i];
            ash_mutex_lock(&sl->mu);
            if (sl->used) {
                pfds[n].fd      = sl->fd;
                pfds[n].events  = (short)(POLLRDNORM | ((sl->tx_len > 0u) ? POLLWRNORM : 0));
                pfds[n].revents = 0;
                pfd_map[n++]    = i;
            }
            ash_mutex_unlock(&sl->mu);
        }

        if (n == 0u) {
            ash_sleep_ms(10u);
            continue;
        }
#ifdef _WIN32
        int ready = WSAPoll(pfds, (ULONG)n, 15);
#else
        int ready = poll(pfds, n, 15);
#endif
        if (ready > 0) {
            for (uint32_t k = 0u; k < n; ++k) {
                short rev = pfds[k].revents;
                if (rev == 0) continue;
                uint32_t id = pfd_map[k];
                if (id == 0x80000001u) {
                    drain_udp_primary(w, txq);
                } else if (id == 0x80000002u) {
                    drain_udp_probe(w, txq);
                } else if (id == 0x80000003u) {
                    accept_tcp_clients(w);
                } else {
                    bool rd = (rev & (POLLRDNORM | POLLERR | POLLHUP)) != 0;
                    bool wr = (rev & POLLWRNORM) != 0;
                    handle_tcp_slot_io(w, id, rd, wr, txq);
                }
            }
        }

        uint64_t now_us = ash_now_us();
        if ((now_us > last_sweep_us) && ((now_us - last_sweep_us) >= 500000ULL)) {
            worker_sweep_tcp(w, now_us);
            last_sweep_us = now_us;
        }
    }
    free(pfds);
    free(pfd_map);
#endif

    free(txq);
}

/* ---------------- Maintenance, Cluster Heartbeat & Prometheus Metrics ---------------- */
size_t ash_server_format_metrics(ash_server_t *srv, char *buf, size_t cap) {
    if ((srv == NULL) || (buf == NULL) || (cap == 0u)) return 0u;
    uint64_t now_us = ash_now_us();
    uint32_t hosts  = srv->has_registry ? ash_registry_online_hosts(&srv->registry, now_us) : 0u;
    uint32_t nodes  = srv->has_registry ? ash_registry_healthy_nodes(&srv->registry, now_us) : 0u;
    uint32_t sess   = srv->has_relay ? ash_relay_active_sessions(&srv->relay, now_us) : 0u;
    uint64_t tconns = ash_atomic_load(&srv->active_tcp_conns);

    uint64_t reg_ok    = srv->has_registry ? ash_atomic_load(&srv->registry.stat_reg_ok) : 0ULL;
    uint64_t auth_fail = srv->has_registry ? ash_atomic_load(&srv->registry.stat_auth_fail) : 0ULL;
    uint64_t lookups   = srv->has_registry ? ash_atomic_load(&srv->registry.stat_lookups) : 0ULL;
    uint64_t notfound  = srv->has_registry ? ash_atomic_load(&srv->registry.stat_notfound) : 0ULL;

    uint64_t fwd_pkts  = srv->has_relay ? ash_atomic_load(&srv->relay.stat_fwd_pkts) : 0ULL;
    uint64_t fwd_bytes = srv->has_relay ? ash_atomic_load(&srv->relay.stat_fwd_bytes) : 0ULL;
    uint64_t drop_auth = srv->has_relay ? ash_atomic_load(&srv->relay.stat_drop_auth) : 0ULL;
    uint64_t drop_qos  = srv->has_relay ? ash_atomic_load(&srv->relay.stat_drop_qos) : 0ULL;
    uint64_t hydrated  = srv->has_relay ? ash_atomic_load(&srv->relay.stat_hydrated) : 0ULL;

    uint64_t drop_rate = ash_atomic_load(&srv->guard.dropped_rate);
    uint64_t drop_pen  = ash_atomic_load(&srv->guard.dropped_penalty);
    uint64_t drop_tcp  = ash_atomic_load(&srv->tcp_backpressure_drops);
    uint64_t rss       = ash_rss_bytes();
    double   cpu_s     = ash_cpu_seconds();

    int n = snprintf(buf, cap,
        "# TYPE ash_online_hosts gauge\n"
        "ash_online_hosts %u\n"
        "# TYPE ash_healthy_relay_nodes gauge\n"
        "ash_healthy_relay_nodes %u\n"
        "# TYPE ash_active_relay_sessions gauge\n"
        "ash_active_relay_sessions %u\n"
        "# TYPE ash_active_tcp_connections gauge\n"
        "ash_active_tcp_connections %llu\n"
        "# TYPE ash_signaling_registrations_total counter\n"
        "ash_signaling_registrations_total %llu\n"
        "# TYPE ash_signaling_auth_failures_total counter\n"
        "ash_signaling_auth_failures_total %llu\n"
        "# TYPE ash_signaling_lookups_total counter\n"
        "ash_signaling_lookups_total %llu\n"
        "# TYPE ash_signaling_notfound_total counter\n"
        "ash_signaling_notfound_total %llu\n"
        "# TYPE ash_relay_forwarded_packets_total counter\n"
        "ash_relay_forwarded_packets_total %llu\n"
        "# TYPE ash_relay_forwarded_bytes_total counter\n"
        "ash_relay_forwarded_bytes_total %llu\n"
        "# TYPE ash_relay_dropped_auth_total counter\n"
        "ash_relay_dropped_auth_total %llu\n"
        "# TYPE ash_relay_dropped_qos_total counter\n"
        "ash_relay_dropped_qos_total %llu\n"
        "# TYPE ash_relay_stateless_hydrated_total counter\n"
        "ash_relay_stateless_hydrated_total %llu\n"
        "# TYPE ash_guard_dropped_rate_total counter\n"
        "ash_guard_dropped_rate_total %llu\n"
        "# TYPE ash_guard_dropped_penalty_total counter\n"
        "ash_guard_dropped_penalty_total %llu\n"
        "# TYPE ash_tcp_backpressure_drops_total counter\n"
        "ash_tcp_backpressure_drops_total %llu\n"
        "# TYPE ash_process_rss_bytes gauge\n"
        "ash_process_rss_bytes %llu\n"
        "# TYPE ash_process_cpu_seconds_total counter\n"
        "ash_process_cpu_seconds_total %.3f\n",
        hosts, nodes, sess,
        (unsigned long long)tconns,
        (unsigned long long)reg_ok,
        (unsigned long long)auth_fail,
        (unsigned long long)lookups,
        (unsigned long long)notfound,
        (unsigned long long)fwd_pkts,
        (unsigned long long)fwd_bytes,
        (unsigned long long)drop_auth,
        (unsigned long long)drop_qos,
        (unsigned long long)hydrated,
        (unsigned long long)drop_rate,
        (unsigned long long)drop_pen,
        (unsigned long long)drop_tcp,
        (unsigned long long)rss,
        cpu_s
    );
    if ((n < 0) || ((size_t)n >= cap)) return 0u;
    return (size_t)n;
}

static void serve_metrics_once(ash_server_t *srv) {
    if (srv->metrics_fd == ASH_INVALID_SOCK) return;
    for (unsigned i = 0u; i < 8u; ++i) {
        struct sockaddr_storage ss;
        socklen_t sl = (socklen_t)sizeof(ss);
        ash_sock_t c = accept(srv->metrics_fd, (struct sockaddr *)&ss, &sl);
        if (c == ASH_INVALID_SOCK) break;

        (void)ash_sock_set_nonblock(c);
        char req[512];
        ash_sleep_ms(1u);
        int r = tcp_recv_nowait(c, (uint8_t *)req, sizeof(req) - 1u);
        if (r > 0) {
            req[r] = '\0';
            char body[2048];
            char resp[2560];
            if (strncmp(req, "GET /healthz", 12u) == 0) {
                const char *mstr = (srv->cfg.mode == ASH_MODE_ID) ? "id"
                                 : (srv->cfg.mode == ASH_MODE_RELAY) ? "relay" : "all";
                int bl = snprintf(body, sizeof(body), "{\"status\":\"ok\",\"mode\":\"%s\"}\n", mstr);
                int hl = snprintf(resp, sizeof(resp),
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                    "Content-Length: %d\r\nConnection: close\r\n\r\n%s",
                    bl, body);
                if (hl > 0) (void)tcp_send_nowait(c, (const uint8_t *)resp, (size_t)hl);
            } else {
                size_t bl = ash_server_format_metrics(srv, body, sizeof(body));
                int hl = snprintf(resp, sizeof(resp),
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\n"
                    "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
                    bl, body);
                if (hl > 0) (void)tcp_send_nowait(c, (const uint8_t *)resp, (size_t)hl);
            }
        }
        ash_sock_close(c);
    }
}

static void maint_loop(void *arg) {
    ash_server_t *srv     = (ash_server_t *)arg;
    uint64_t last_hb_us   = 0ULL;
    uint64_t last_bytes   = 0ULL;
    uint64_t last_rate_us = ash_now_us();
    uint32_t est_kbps     = 0u;

    ash_sock_t hb_sock = ASH_INVALID_SOCK;
    if (srv->has_relay && (srv->cfg.upstream_id_ep.fam != 0u)) {
        hb_sock = ash_udp_bind("::", 0u, false, 65536);
    }

    while (ash_atomic_load(&srv->running) != 0ULL) {
        ash_sleep_ms(50u);
        uint64_t now_us = ash_now_us();

        if (srv->has_registry) ash_registry_sweep_step(&srv->registry, now_us);
        if (srv->has_relay)    ash_relay_sweep_step(&srv->relay, now_us);
        serve_metrics_once(srv);

        /* Measure rolling Relay bandwidth utilization & send signed Cluster Node Heartbeat */
        if (srv->has_relay && ((now_us - last_rate_us) >= 1000000ULL)) {
            uint64_t cur_bytes = ash_atomic_load(&srv->relay.stat_fwd_bytes);
            uint64_t dt_us     = now_us - last_rate_us;
            uint64_t dbytes    = (cur_bytes >= last_bytes) ? (cur_bytes - last_bytes) : 0ULL;
            est_kbps           = (uint32_t)((dbytes * 8000ULL) / dt_us);
            last_bytes         = cur_bytes;
            last_rate_us       = now_us;
        }

        if ((hb_sock != ASH_INVALID_SOCK) &&
            ((last_hb_us == 0ULL) || ((now_us - last_hb_us) >= 3000000ULL))) {
            last_hb_us = now_us;
            ash_msg_node_hb_t hb;
            memset(&hb, 0, sizeof(hb));
            hb.node_id         = srv->cfg.node_id;
            hb.tier_max        = srv->cfg.node_tier_max;
            hb.pool_id         = srv->cfg.node_pool_id;
            hb.region_id       = srv->cfg.region_id;
            hb.active_sessions = ash_relay_active_sessions(&srv->relay, now_us);
            hb.used_kbps       = est_kbps;
            hb.cap_kbps        = (srv->cfg.total_bw_kbps != 0u) ? srv->cfg.total_bw_kbps : 1000000u;
            hb.ts_ms           = ash_wall_ms();
            hb.public_udp      = srv->cfg.public_udp_ep;
            hb.public_tcp      = srv->cfg.public_tcp_ep;
            if ((hb.public_udp.port == 0u) && (srv->bound_udp_port != 0u)) {
                hb.public_udp.port = srv->bound_udp_port;
            }
            if ((hb.public_tcp.port == 0u) && (srv->bound_tcp_port != 0u)) {
                hb.public_tcp.port = srv->bound_tcp_port;
            }

            uint8_t pkt[160];
            size_t plen = ash_build_node_hb(pkt, sizeof(pkt), srv->cfg.cluster_secret, &hb);
            struct sockaddr_in6 dst6;
            if ((plen > 0u) && (ash_ep_to_sockaddr6(&srv->cfg.upstream_id_ep, &dst6) != 0)) {
                (void)sendto(hb_sock, (const char *)pkt, (ash_io_len_t)plen, 0,
                             (const struct sockaddr *)&dst6, (socklen_t)sizeof(dst6));
            }
        }
    }

    if (hb_sock != ASH_INVALID_SOCK) {
        ash_sock_close(hb_sock);
    }
}

/* ---------------- Lifecycle Management ---------------- */
ash_server_t *ash_server_create(const ash_server_cfg_t *cfg) {
    if (cfg == NULL) return NULL;
    ash_server_t *srv = (ash_server_t *)calloc(1u, sizeof(ash_server_t));
    if (srv == NULL) return NULL;

    srv->cfg        = *cfg;
    srv->metrics_fd = ASH_INVALID_SOCK;
    for (uint32_t i = 0u; i < ASH_MAX_WORKERS; ++i) {
        srv->workers[i].udp_fd        = ASH_INVALID_SOCK;
        srv->workers[i].probe_fd      = ASH_INVALID_SOCK;
        srv->workers[i].tcp_listen_fd = ASH_INVALID_SOCK;
#ifdef __linux__
        srv->workers[i].ep_fd         = -1;
#endif
    }

    bool secret_set = false;
    for (size_t i = 0u; i < 32u; ++i) {
        if (srv->cfg.cluster_secret[i] != 0u) secret_set = true;
    }
    if (!secret_set) {
        (void)ash_csprng(srv->cfg.cluster_secret, 32u);
    }

    bool lic_set = false;
    for (size_t i = 0u; i < 32u; ++i) {
        if (srv->cfg.license_secret[i] != 0u) lic_set = true;
    }
    if (!lic_set) {
        memcpy(srv->cfg.license_secret, srv->cfg.cluster_secret, 32u);
    }

    bool want_registry = (cfg->mode == ASH_MODE_ALL) || (cfg->mode == ASH_MODE_ID);
    bool want_relay    = (cfg->mode == ASH_MODE_ALL) || (cfg->mode == ASH_MODE_RELAY);

#ifdef __linux__
    uint32_t nw = cfg->num_workers;
    if (nw == 0u) {
        uint32_t cpus = ash_cpu_count();
        nw = (cpus > 8u) ? 8u : cpus;
    }
    if (nw > ASH_MAX_WORKERS) nw = ASH_MAX_WORKERS;
    /* Port 0 auto-bind cannot share random ephemeral port via SO_REUSEPORT reliably across sockets */
    if ((cfg->udp_port == 0u) && (nw > 1u)) nw = 1u;
    srv->num_workers = nw;
#else
    /* Windows UDP unicast does not load-balance SO_REUSEADDR across multiple sockets */
    srv->num_workers = 1u;
#endif

    if (!ash_ip_guard_init(&srv->guard, 4096u, cfg->ip_sig_rps, cfg->ip_max_strikes, 10000000ULL)) {
        ash_server_destroy(srv);
        return NULL;
    }
    srv->guard.max_pins_per_day = cfg->ip_new_numbers_per_day;
    srv->has_guard = true;

    if (!ash_cookie_jar_init(&srv->cookies, 30000000ULL)) {
        ash_server_destroy(srv);
        return NULL;
    }
    srv->has_cookies = true;

    if (want_registry) {
        ash_registry_cfg_t rcfg;
        memset(&rcfg, 0, sizeof(rcfg));
        rcfg.allow_v1_unauth = cfg->allow_v1_unauth;
        rcfg.host_ttl_us     = cfg->host_ttl_sec * 1000000ULL;
        rcfg.node_ttl_us     = 15000000ULL;
        rcfg.tier_kbps[0]    = cfg->free_kbps;
        rcfg.tier_kbps[1]    = cfg->pro_kbps;
        rcfg.tier_kbps[2]    = cfg->vip_kbps;
        rcfg.tier_kbps[3]    = cfg->dedicated_kbps;
        memcpy(rcfg.license_secret, srv->cfg.license_secret, 32u);
        rcfg.keystore_path   = cfg->keystore_path;
        if (!ash_registry_init(&srv->registry, cfg->max_hosts, &rcfg)) {
            ash_server_destroy(srv);
            return NULL;
        }
        srv->has_registry = true;
    }

    if (want_relay) {
        ash_relay_cfg_t rlcfg;
        memset(&rlcfg, 0, sizeof(rlcfg));
        rlcfg.sess_ttl_us           = cfg->sess_ttl_sec * 1000000ULL;
        rlcfg.stateless_window_min  = 30u;
        rlcfg.node_pool_id          = cfg->node_pool_id;
        rlcfg.tier_kbps[0]          = cfg->free_kbps;
        rlcfg.tier_kbps[1]          = cfg->pro_kbps;
        rlcfg.tier_kbps[2]          = cfg->vip_kbps;
        rlcfg.tier_kbps[3]          = cfg->dedicated_kbps;
        rlcfg.free_pool_total_kbps  = cfg->free_pool_kbps;
        rlcfg.total_bw_kbps         = cfg->total_bw_kbps;
        memcpy(rlcfg.cluster_secret, srv->cfg.cluster_secret, 32u);
        if (!ash_relay_init(&srv->relay, cfg->max_sessions, &rlcfg)) {
            ash_server_destroy(srv);
            return NULL;
        }
        srv->has_relay = true;
    }

    uint32_t tcp_per_worker = (cfg->max_tcp_conns + srv->num_workers - 1u) / srv->num_workers;
    if (tcp_per_worker < 16u) tcp_per_worker = 16u;

    bool reuse = (srv->num_workers > 1u);
    for (uint32_t i = 0u; i < srv->num_workers; ++i) {
        ash_worker_t *w = &srv->workers[i];
        w->srv       = srv;
        w->worker_id = i;
        w->tcp_cap   = (cfg->tcp_port != 0u) ? tcp_per_worker : 0u;

        if (w->tcp_cap > 0u) {
            w->tcp_slots = (ash_tcp_slot_t *)calloc(w->tcp_cap, sizeof(ash_tcp_slot_t));
            if (w->tcp_slots == NULL) {
                ash_server_destroy(srv);
                return NULL;
            }
            for (uint32_t s = 0u; s < w->tcp_cap; ++s) {
                ash_mutex_init(&w->tcp_slots[s].mu);
                w->tcp_slots[s].fd = ASH_INVALID_SOCK;
            }
        }

        uint16_t req_udp = (i == 0u) ? cfg->udp_port : srv->bound_udp_port;
        w->udp_fd = ash_udp_bind(cfg->bind_ip, req_udp, reuse, 8 * 1024 * 1024);
        if (w->udp_fd == ASH_INVALID_SOCK) {
            ash_server_destroy(srv);
            return NULL;
        }
        if (i == 0u) {
            srv->bound_udp_port = ash_sock_bound_port(w->udp_fd);
        }

        if (srv->has_registry && cfg->enable_nat_probe) {
            uint16_t want_probe = (i == 0u)
                ? ((cfg->udp_port != 0u) ? (uint16_t)(srv->bound_udp_port + 1u) : 0u)
                : srv->bound_probe_port;
            w->probe_fd = ash_udp_bind(cfg->bind_ip, want_probe, reuse, 1024 * 1024);
            if ((i == 0u) && (w->probe_fd != ASH_INVALID_SOCK)) {
                srv->bound_probe_port = ash_sock_bound_port(w->probe_fd);
            }
        }

        if (cfg->tcp_port != 0u) {
            uint16_t req_tcp = (i == 0u) ? cfg->tcp_port : srv->bound_tcp_port;
            /* Port 65535 serves as "ephemeral auto TCP port" for test suites */
            if ((i == 0u) && (req_tcp == 65535u)) req_tcp = 0u;
            w->tcp_listen_fd = ash_tcp_listen(cfg->bind_ip, req_tcp, reuse, 2048);
            if (w->tcp_listen_fd == ASH_INVALID_SOCK) {
                ash_server_destroy(srv);
                return NULL;
            }
            if (i == 0u) {
                srv->bound_tcp_port = ash_sock_bound_port(w->tcp_listen_fd);
            }
        }

#ifdef __linux__
        w->ep_fd = epoll_create1(0);
        if (w->ep_fd < 0) {
            ash_server_destroy(srv);
            return NULL;
        }
        struct epoll_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.events   = EPOLLIN;
        ev.data.u64 = 1ULL;
        (void)epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, w->udp_fd, &ev);
        if (w->probe_fd != ASH_INVALID_SOCK) {
            ev.data.u64 = 2ULL;
            (void)epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, w->probe_fd, &ev);
        }
        if (w->tcp_listen_fd != ASH_INVALID_SOCK) {
            ev.data.u64 = 3ULL;
            (void)epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, w->tcp_listen_fd, &ev);
        }
#endif
    }

    if (cfg->metrics_port != 0u) {
        uint16_t mp = (cfg->metrics_port == 65535u) ? 0u : cfg->metrics_port;
        srv->metrics_fd = ash_tcp_listen(cfg->metrics_bind_ip, mp, false, 64);
        if (srv->metrics_fd != ASH_INVALID_SOCK) {
            srv->bound_metrics_port = ash_sock_bound_port(srv->metrics_fd);
        }
    }

    return srv;
}

bool ash_server_start(ash_server_t *srv) {
    if ((srv == NULL) || srv->started) return false;
    ash_atomic_store(&srv->running, 1ULL);

    uint32_t started_workers = 0u;
    for (uint32_t i = 0u; i < srv->num_workers; ++i) {
        if (!ash_thread_start(&srv->workers[i].thread, worker_loop, &srv->workers[i], (int)i)) {
            ash_atomic_store(&srv->running, 0ULL);
            for (uint32_t j = 0u; j < started_workers; ++j) {
                ash_thread_join(&srv->workers[j].thread);
            }
            return false;
        }
        started_workers += 1u;
    }

    if (!ash_thread_start(&srv->maint_thread, maint_loop, srv, -1)) {
        ash_atomic_store(&srv->running, 0ULL);
        for (uint32_t j = 0u; j < started_workers; ++j) {
            ash_thread_join(&srv->workers[j].thread);
        }
        return false;
    }

    srv->started = true;
    return true;
}

void ash_server_stop(ash_server_t *srv) {
    if ((srv == NULL) || !srv->started) return;
    ash_atomic_store(&srv->running, 0ULL);
    ash_thread_join(&srv->maint_thread);
    for (uint32_t i = 0u; i < srv->num_workers; ++i) {
        ash_thread_join(&srv->workers[i].thread);
    }
    srv->started = false;
}

void ash_server_destroy(ash_server_t *srv) {
    if (srv == NULL) return;
    if (srv->started) {
        ash_server_stop(srv);
    }

    if (srv->metrics_fd != ASH_INVALID_SOCK) {
        ash_sock_close(srv->metrics_fd);
        srv->metrics_fd = ASH_INVALID_SOCK;
    }

    for (uint32_t i = 0u; i < ASH_MAX_WORKERS; ++i) {
        ash_worker_t *w = &srv->workers[i];
        if (w->tcp_slots != NULL) {
            for (uint32_t s = 0u; s < w->tcp_cap; ++s) {
                ash_mutex_lock(&w->tcp_slots[s].mu);
                (void)tcp_close_slot_locked(srv, w, &w->tcp_slots[s]);
                ash_mutex_unlock(&w->tcp_slots[s].mu);
                ash_mutex_destroy(&w->tcp_slots[s].mu);
            }
            free(w->tcp_slots);
            w->tcp_slots = NULL;
        }
        if (w->udp_fd != ASH_INVALID_SOCK)        ash_sock_close(w->udp_fd);
        if (w->probe_fd != ASH_INVALID_SOCK)      ash_sock_close(w->probe_fd);
        if (w->tcp_listen_fd != ASH_INVALID_SOCK) ash_sock_close(w->tcp_listen_fd);
#ifdef __linux__
        if (w->ep_fd >= 0) close(w->ep_fd);
#endif
    }

    if (srv->has_registry) ash_registry_destroy(&srv->registry);
    if (srv->has_relay)    ash_relay_destroy(&srv->relay);
    if (srv->has_guard)    ash_ip_guard_destroy(&srv->guard);
    if (srv->has_cookies)  ash_cookie_jar_destroy(&srv->cookies);
    ash_secure_zero(srv, sizeof(*srv));
    free(srv);
}

uint16_t ash_server_udp_port(const ash_server_t *srv) {
    return (srv != NULL) ? srv->bound_udp_port : 0u;
}

uint16_t ash_server_probe_port(const ash_server_t *srv) {
    return (srv != NULL) ? srv->bound_probe_port : 0u;
}

uint16_t ash_server_tcp_port(const ash_server_t *srv) {
    return (srv != NULL) ? srv->bound_tcp_port : 0u;
}

uint16_t ash_server_metrics_port(const ash_server_t *srv) {
    return (srv != NULL) ? srv->bound_metrics_port : 0u;
}

size_t ash_server_allocated_bytes(const ash_server_t *srv) {
    if (srv == NULL) return 0u;
    size_t total = sizeof(*srv) + ash_ip_guard_memory_bytes(&srv->guard);
    if (srv->has_registry) total += ash_registry_memory_bytes(&srv->registry);
    if (srv->has_relay)    total += ash_relay_memory_bytes(&srv->relay);
    for (uint32_t i = 0u; i < srv->num_workers; ++i) {
        total += (size_t)srv->workers[i].tcp_cap * sizeof(ash_tcp_slot_t);
    }
    total += (size_t)ash_atomic_load(&srv->active_tcp_conns) * sizeof(ash_tcp_buf_t);
    return total;
}
