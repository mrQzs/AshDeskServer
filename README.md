# AshDeskServer — 极帧高性能信令注册（ID / Rendezvous）与中继转发（Relay / TURN）服务器

`AshDeskServer` 是为 `AshDesk`（极帧远程桌面）设计的生产级零外部依赖 **C17** 服务端基础设施，同时承担：

1. **信令 / 注册服务器（ID / Rendezvous Server）**：维护海量在线设备 ID 状态、毫秒级非阻塞心跳检测、**Ed25519 公私钥防抢注身份鉴权**、双端口 NAT 映射类型探测（Cone vs Symmetric 步长识别），协助主控端与被控端交换公网/内网/IPv6/端口映射候选地址实施 **UDP / TCP 同步打洞**。一旦 P2P 打洞成功，音视频流与控制指令直接在两端之间经 DTLS 点对点加密传输，**服务器带宽消耗降为 0**。
2. **中继 / 转发服务器（Relay / TURN Server）**：当两端处于严格对称型 NAT（Symmetric NAT）或企业防火墙封禁 UDP 导致 P2P 打洞失败时，提供**零解密（Zero-Decryption）端到端密文转发**，内置 **TCP / TLS-443 伪装隧道（支持异构 `TCP 443 ↔ UDP` 桥接）** 穿透严苛企业防火墙，并完整实现商业远控核心盈利能力：**免费版限速 / 付费高速通道 / VIP 极速通道 / 企业专享节点池隔离**。

---

## 核心架构特性

### 1. 极致性能、低内存与超高并发
- **热路径零堆内存分配（Zero Heap Allocation on Hot Path）**：在线设备表、中继会话表、源 IP 反滥用限流表全部采用**启动期预分配 + 64 路缓存行隔离分片（Cache-Line Separated Shards）**开放寻址扁平数组，转发期间 `0` 次 `malloc`/`free`、无 GC 停顿毛刺。
- **Linux 多核无锁网络栈**：基于 `SO_REUSEPORT` 多核内核哈希分流 + `epoll` + `recvmmsg()` / `sendmmsg()` 批量系统调用（单次收发最高 64 个数据报），支持 CPU 核心亲和性绑定（`pthread_setaffinity_np`）；Windows 开发调试端基于双栈非阻塞 `WSAPoll`。
- **超低单连接内存开销**：
  - 每台注册在线设备槽位约 `344 B`（10 万台在线设备仅约 `34 MB`）；
  - 每路活动中继会话槽位约 `192 B`（10 万路并发会话状态仅约 `19 MB`）；
  - 空闲 TCP 槽位仅 `72 B`，活动 TCP 443 隧道固定上限 `12 KB`（4 KB 接收拼帧 + 8 KB 反队头阻塞发送环），满水位按整帧原子丢弃旧媒体包，**绝不堆积多秒历史视频延迟、绝不破坏帧边界**。

### 2. 双形态弹性部署（单机合一 & 分布式无状态中继集群）
- **单机合一模式（`--mode all`）**：单进程、单 UDP 端口（默认 `44200`）+ 可选 TCP `443` 端口同时提供信令与中继，**100% 向下兼容 AshDesk 现有 `adp_rdv` v1 客户端与被控端（零改动即插即用）**。v1 另认在线状态查询 `PRESENCE`（10）→ `PRESENCE_OK`（11，带主机标志）/ `NOTFOUND`：不建中继会话、不通知主机，两种回应都比请求短（不当反射放大器），走同一个按源 IP 的信令限频。v1 的 NAT 测试照 AshDesk 自带的 `adrd_rdv` 回：`NAT_TEST`（7）发到主端口和探测端口（主端口 + 1），各自在原端口回 `NAT_OK`（8，看到的来源）；探测端口上的测试带着活会话的 sess 和令牌时，再从主端口给会话另一侧发 `NAT_PEER`（9，测试方在两个端口上的映射，对称型 NAT 预测端口用）。格式对、只是服务端不处理的 v1 消息（比如回应类型）直接忽略，不记违规；解不开的照样记。
  - **v1 号码归属**（AshDesk《号码连接设计》§4.2，和 `adrd_rdv` 同一套线上格式）：名字是 9 位数字（首位 1–9）的登记要证明归属。不带证明的 `REG` 回 `REG_CHAL`（12，8 字节随机数）；主机在 `REG` 尾部带上 `0xE2 | 公钥 32 | 随机数 8 | 签名 64` 再发一遍，签的是 `"AshDesk number v1" ‖ 随机数 ‖ 号码`。号码归第一把登记它的密钥（和 v2 用同一个钉住的公钥、同一个 `--keystore`，重启不丢）；别的密钥来登记回 `REG_TAKEN`（13）。地址没变的保活不带证明。随机数 = HMAC(进程内密钥, 来源地址 ‖ 60 秒时间片) 的前 8 字节，认当前和上一片：换个地址重放不认，伪造来源的人收不到随机数、服务不替他验签。别的名字照旧不验。一个来源（IPv4 按地址、IPv6 按 /48：一个用户手里通常有一整个 /56 或 /48，按 /64 算的话换个子网又是一份额度）一天最多新占 300 个号码（`--limit-new-numbers`，0 = 不限），超了的不回；它已经占的号码照常登记。和 `adrd_rdv` 的差别：钥匙库只增不减（没有 180 天回收）；查找和在线状态没有单独的限流，走已有的按源 IP 信令限频（默认每秒 120 个）和违规封禁；钉住的公钥和在线表共用槽位，登记过的号码总数接近 `--max-hosts` 的 1.5 倍以后，离线号码的归属会被新登记挤出内存（v2 的钉住也一样），到那个量级之前要把归属表单独拆出来。
  - **主机标志 `0x10`** 是 AshDesk 的“接受连接密码”（`RDV_HF_PASSWORD`），原样透传；本服务原来占用这一位的“支持 TCP 打洞”挪到 `0x20`（没有已部署的主机置过它）。
- **分布式集群模式（`--mode id` + 多地域 `--mode relay`）**：
  - 边缘 `Relay` 节点无需连接任何数据库或 Redis，每 3 秒向 `ID` 节点发送 `HMAC-SHA256` 签名的负载心跳（活跃会话数、实时带宽占用、最大档位、专享池 `pool_id`、公网 UDP/TCP 地址）；
  - `ID` 节点按商业授权档位与节点负载就近调度最优 `Relay` 节点，并签发 **36 字节无状态 `HMAC-SHA256` 中继票据（Relay Ticket）** 与确定性派生令牌 `(sess, tok)`；
  - **0-RTT 故障自愈**：即使 `Relay` 节点重启，两端后续发出的首个 `'R'` 媒体包即可在 `0.4 µs` 内完成无状态验签并自动重建转发会话。

### 3. 多层安全加固与抗 DDoS
- **Ed25519 设备防抢注鉴权（RFC 8032）**：内置零依赖恒定时间签名生成与 Shamir 双标量加速验签（严格校验 `S < L` 防签名可锻造及 `y < 2^255-19` 规范点编码）；设备首次注册自动绑定公钥（TOFU + 本地校验持久库 `--keystore`），任何未持有对应私钥的攻击者及 v1 降级包均无法覆盖或劫持设备 ID。
- **无状态源地址 Cookie 防反射放大**：基于双密钥滚动 `HMAC-SHA256` Cookie（`--cookie adaptive|always`），未验证源 IP 前回包固定 `20 B`（严格小于请求包），服务端零状态内存消耗抵御伪造源 IP 洪水。
- **抗 HashDoS 与 IPv6 `/64` 前缀惩罚限流**：全表采用 CSPRNG 随机种子的 **SipHash-2-4** 哈希；源限流器对 IPv4 按 `/32`、对 IPv6 按 `/64` 子网前缀做 4 路组相联令牌限频与错误令牌熔断封禁。
- **零信任密文转发**：服务端不接触任何会话密钥，两端音视频与控制流全程由客户端与主机之间的 DTLS 1.2（`ECDHE-PSK-CHACHA20-POLY1305`）端到端加密保护。

### 4. 商业分级限速与专享节点模型
| 商业档位 | 枚举值 | 默认单会话速率 | 典型商业定位 |
|---|---|---|---|
| **免费公共通道** | `ASH_TIER_FREE (0)` | `--free-bw-kbps`（如 `2000` kbps） | 免费版基础运维，受 `--free-pool-kbps` 免费总池上限约束，绝不挤占付费用户带宽 |
| **付费高速通道** | `ASH_TIER_PRO (1)` | `20,000` kbps（20 Mbps） | 1080p60 流畅远程办公 |
| **VIP 极速通道** | `ASH_TIER_VIP (2)` | `100,000` kbps（100 Mbps） | 4K 高刷设计 / 游戏低延迟通道 |
| **企业专享节点** | `ASH_TIER_DEDICATED (3)` | 不限速（物理独享） | `--pool-id <企业ID>` 专属中继节点，仅放行匹配 `pool_id` 的签名票据 |

同时通过信令 `relay_max_kbps` 向两端宣告会话配额，联动客户端 `rdv_clamp_bitrate_bps` 从编码源头平滑钳制码率，避免限速丢包卡顿。

---

## 构建与质量门禁

### 实测性能与质量门禁结果（本机实测）

| 指标 / 检查项 | Linux Release（WSL `clang -O3`，`epoll` + `recvmmsg`/`sendmmsg`） | Windows（MSVC 2022 `RelWithDebInfo`，`WSAPoll`） |
|---|---|---|
| **单线程中继转发吞吐**（1200 B 载荷） | **`542,174 pkt/s`（`5.24 Gbit/s`，80,000/80,000 零丢包）** | `103,185–116,666 pkt/s`（`1.00–1.13 Gbit/s`） |
| **单跳中继转发延迟**（500 样本） | **`P50 = 25 µs`（0.025 ms），`P99 = 73 µs`（0.073 ms）** | `P50 = 59 µs`，`P99 = 156 µs` |
| **Ed25519 签名注册验签吞吐**（单核） | **`2,261 次/s`**（8 核 `SO_REUSEPORT` 可线性扩展至 ~1.8 万次/s） | `1,138 次/s` |
| **内存占用**（预置 6.5 万设备 + 6.5 万会话容量） | 活跃期进程 **RSS `11.31 MB`**，满载上界 `70.04 MB` | 进程工作集 `76.14 MB` |
| **编译器零警告门禁** | GCC 13.3 & Clang 18 `-Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Werror` **0 警告** | MSVC 19.44 `/W4 /WX` **0 警告** |
| **静态分析 & Sanitizers** | `Clang-Tidy` **0 告警**、`Cppcheck` **0 告警**、`ASan+UBSan+LSan` / `TSan` **11/11 全过**、4.5 万畸形包 Fuzz **0 泄漏** | MSVC `AddressSanitizer` **11/11 全过** |

### Windows（MSVC 2022 + Ninja，`/W4 /WX` 零警告）
```bat
build.bat
.\build\ash_gtest.exe
.\build\ash_bench.exe --hosts 1000 --packets 50000
```

### Linux / WSL（GCC + Clang `-Werror` + ASan/UBSan/LSan + TSan + Clang-Tidy + Cppcheck + Fuzz）
```bash
bash tools/verify_all.sh
```

---

## 快速上手与集群部署示例

### 1. 单机一键启动（兼容现有 `AshDesk` 客户端 + 开启 TCP 443 防火墙穿透 + 免费限速 2 Mbps）
```bash
./ash_server \
  --mode all \
  --port 44200 \
  --tcp-port 443 \
  --free-bw-kbps 2000 \
  --free-pool-kbps 50000 \
  --metrics-port 44280 \
  --keystore ./devices_pin.db
```
现有 `AshDesk` 被控端与主控端可直接连接：
```bash
# 被控端（Host）
adrd_host --rendezvous your-HostName@<服务器IP>:44200 --psk-stored

# 主控端（Client）
adrd_client --connect your-HostName@<服务器IP>:44200 --psk-stored

# 号码连接：被控端登记本机号码并开连接密码；主控端按号码和密码连（号码归属由服务端验，见上面“v1 号码归属”）
adrd_host --rendezvous <服务器IP>:44200 --number --password
adrd_client --connect <9 位号码>@<服务器IP>:44200 --password <8 位密码>
```

### 2. 签发商业高速通道 / 企业专享节点授权 Token（`ash_ctl`）
```bash
# 生成 32 字节（64位十六进制）集群主密钥与商业授权密钥
CLUSTER_KEY=$(./ash_ctl gen-secret)
LICENSE_KEY=$(./ash_ctl gen-secret)

# 为付费用户签发 30 天有效期、50 Mbps 上限的 VIP 高速通道 Token
VIP_TOKEN=$(./ash_ctl issue-license --secret "$LICENSE_KEY" --tier vip --kbps 50000 --days 30)

# 校验并查看 Token 声明
./ash_ctl verify-license --secret "$LICENSE_KEY" --token "$VIP_TOKEN"
```

### 3. 分布式部署（1 台信令中心 + 多台边缘免费/VIP/企业专享中继节点）
```bash
# 中心信令服务器（ID Server）
./ash_server --mode id --port 44200 --cluster-key "$CLUSTER_KEY" --license-key "$LICENSE_KEY" \
  --keystore /var/lib/ashdesk/devices.db --metrics-port 44280

# 边缘节点 1：公共免费+高速共享中继节点（华东）
./ash_server --mode relay --node-id 101 --port 44200 --tcp-port 443 \
  --cluster-key "$CLUSTER_KEY" \
  --public-udp 203.0.113.10:44200 --public-tcp 203.0.113.10:443 \
  --id-server 198.51.100.1:44200 \
  --free-bw-kbps 2000 --free-pool-kbps 100000 --total-bw-kbps 1000000

# 边缘节点 2：企业专享独享带宽节点（仅服务 pool_id=888 的企业票据）
./ash_server --mode relay --node-id 201 --pool-id 888 --port 44200 --tcp-port 443 \
  --cluster-key "$CLUSTER_KEY" \
  --public-udp 203.0.113.20:44200 --public-tcp 203.0.113.20:443 \
  --id-server 198.51.100.1:44200
```

### 4. Linux 生产环境内核高并发调优建议（`/etc/sysctl.d/99-ashdesk.conf`）
```ini
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.netdev_max_backlog = 65536
net.core.somaxconn = 16384
net.ipv4.ip_local_port_range = 10240 65535
```

### 5. 用 systemd 常驻（单机合一）
`deploy/ashdesk-server.service`：以 systemd 的临时用户运行（只给绑定 443 的权限），设备库放在 `/var/lib/ashdesk-server`，崩溃自动重启、开机自启。
```bash
# 在 Linux 上（或 WSL 里静态链接：-DCMAKE_EXE_LINKER_FLAGS=-static，服务端不查 DNS，可以静态链接）编出 ash_server 后
install -d /opt/ashdesk-server && install -m 755 ash_server /opt/ashdesk-server/
install -m 644 deploy/ashdesk-server.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now ashdesk-server
journalctl -u ashdesk-server -f        # 日志；/metrics 只在本机 127.0.0.1:18388
```

## 许可

本仓库按 [GNU Affero General Public License v3.0](LICENSE)（AGPL-3.0）发布：把改过的服务器拿出来对外提供服务时，要按同样的许可公开改动。
AshDesk 的客户端、主机是另外的程序，经网络和本服务器通信，不受这份许可约束。
