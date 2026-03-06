# TLS-VPN 项目技术说明书

> 版本基准：commit `0b4aeb078ef20f99df212e765cab14c4b6a55145`
> 本文档覆盖 TLS-VPN 项目全部核心模块的架构设计、协议细节、数据流与实现逻辑，
> 以函数/struct 级别的源码引用为锚点，配合流程图与时序图，构成完整的技术参考。

## 章节目录

- [第一章：项目总览与模块地图](#第一章-项目总览与模块地图) — 项目定位、两段式安全模型、仓库结构、系统分层、消息协议、运行模型、端到端数据流
- [第二章：控制面与协议框架](#第二章-控制面与协议框架) — 应用层消息协议、控制服务器、控制客户端、API 协议
- [第三章：网络系统实现与日志基础](#第三章-网络系统实现与日志基础) — TUN 跨平台实现、IP 地址池、路由/DNS 管理、NAT 规则、日志轮转与内存缓冲
- [第四章：端到端运行链路与阶段总结](#第四章-端到端运行链路与阶段总结) — 服务端启动链路、证书 Bootstrap、连接建立、数据包穿透、连接维护、函数调用链索引
- [第五章：证书、配置与 Token 安全链路](#第五章-证书配置与-token-安全链路) — PKI 拓扑、证书生成/加载/约束、VPNConfig 结构、Token 生命周期、安全全景与改进点
- [第六章：生命周期与退出机制](#第六章-生命周期与退出机制) — Daemon 启动与自守护、跨平台信号处理、两条退出路径（OS 信号/IPC Shutdown）、VPNService 资源清理总闸门、服务端/客户端子系统退出细节（路由回滚、DNS 恢复、NAT 清理、TUN 释放）

---

## 第一章 项目总览与模块地图

本章建立对 TLS-VPN 的整体认知：项目定位、安全模型、仓库结构、系统分层与核心模块职责，最后附完整的端到端数据流与时序图。

---

### 1.1 项目定位与安全模型

TLS-VPN 是一个以 **TLS 为加密/认证外壳 + TUN 虚拟网卡承载三层 IP 数据** 的自包含 VPN 系统，集成了终端 UI（TUI）、自建 PKI、Token 注册体系与跨平台支持。

项目采用**两段式安全模型**：

**第一段 — 证书申请阶段（Token 驱动）**

客户端用 Token（本质是 32 字节 AES-256 key）对 CSR 加密，提交给 `CertAPIServer`（HTTP 8081）；服务端校验 Token（有效、未使用、未过期），用 CA 私钥签发客户端证书，再以同一 Token key 加密回传。整个 bootstrap 流程不依赖任何预置证书。

**第二段 — VPN 数据通道阶段（mTLS）**

真实 VPN 隧道（TCP 8080）强制要求 TLS 1.3 + 双向证书认证（`RequireAndVerifyClientCert`）。服务端握手后显式检查 `PeerCertificates`，没有客户端证书则直接拒绝连接。Token 不参与此阶段，只用于 bootstrap。

```
Token 申请证书（一次性）
    客户端 --[AES-GCM 加密 CSR]--> CertAPIServer:8081
    CertAPIServer --[CA 签发]--> 客户端证书
    ↓
VPN 数据通道（长连接）
    客户端 --[TLS 1.3 + mTLS]--> VPNServer:8080
```

---

### 1.2 仓库结构（`source/` 目录）

#### 入口与编排

| 文件 | 职责 |
|------|------|
| `main.go` | 程序入口，命令分发（`--service`/`--stop`/`--status`/默认），实现"Smart 启动"：自动拉起后台 daemon 并进入 TUI |
| `vpn_service.go` | 领域服务层，持有 VPNServer、VPNClient、CertAPIServer、CertificateManager、TokenManager 并编排其生命周期 |
| `config.go` | 配置结构体 `VPNConfig`、默认值、JSON 加载/写回、校验 |

#### VPN 数据面

| 文件 | 职责 |
|------|------|
| `vpn_server.go` | mTLS listener + IP 池分配 + TUN 转发 + 会话管理 + 超时清理 |
| `vpn_client.go` | mTLS dial + 握手状态机 + TUN 配置 + 路由设置 + 心跳 + 重连 |
| `tun_interface.go` | TUN 跨平台抽象接口（`ReadPacket`/`WritePacket`/`Close`/`Name`） |
| `tun_device_unix.go` | Linux/macOS TUN 实现（`/dev/net/tun` + `ioctl(TUNSETIFF)` + ip 命令） |
| `tun_device_windows.go` | Windows TUN 实现（Wintun 驱动 + ring buffer） |

#### 网络配置

| 文件 | 职责 |
|------|------|
| `ip_pool.go` | 虚拟地址池（CIDR 初始化、Allocate/Release、租约过期） |
| `route_manager.go` | Unix 路由管理（`ip route add/del` 或 netlink） |
| `route_manager_windows.go` | Windows 路由管理（`route ADD` 或 IP Helper API） |
| `iptables_nat.go` | Linux NAT 转发规则（MASQUERADE + FORWARD + 退出清理） |

#### 证书与身份

| 文件 | 职责 |
|------|------|
| `cert_manager.go` | 自建 CA 生成（RSA 4096，10年）、server cert 生成（1年）、TLS 配置（强制 TLS 1.3 + mTLS） |
| `cert_api_server.go` | HTTP 8081：接收加密 CSR、校验 Token、签发客户端证书、加密返回 |

#### Token 体系

| 文件 | 职责 |
|------|------|
| `token_manager.go` | Token 元数据管理（生成/校验/单次标记/过期清理） |
| `token_crypto.go` | AES-GCM 加密/解密（`EncryptWithToken`/`DecryptWithToken`） |
| `token_file.go` | Token 落盘（JSON 文件，`key_hex` 字段，0600 权限） |

#### 控制面与协议

| 文件 | 职责 |
|------|------|
| `control_server.go` | Unix Socket / TCP 本地控制 API（供 TUI 调用） |
| `control_client.go` | 控制 API 客户端（TUI 侧，IPC 发送命令、查询状态） |
| `protocol_message.go` | 数据通道消息帧定义与编解码（5 字节固定头） |
| `api_protocol.go` | 控制 API 请求/响应结构定义 |

#### 运行方式与平台适配

| 文件 | 职责 |
|------|------|
| `daemon_unix.go` / `daemon_windows.go` | 以系统服务/守护进程方式运行的封装 |
| `signal_unix.go` / `signal_windows.go` | SIGINT/SIGTERM 信号处理，触发优雅退出 |
| `constants_unix.go` / `constants_windows.go` | 平台默认路径、接口名、Socket 路径等常量 |

#### TUI 界面

| 文件 | 职责 |
|------|------|
| `tui_app.go` | TUI 主循环、全局状态（当前页面、连接对象、配置） |
| `tui_handlers.go` | UI 事件 → 业务操作（调用 ControlClient IPC 命令） |
| `tui_menus.go` | 菜单树与快捷键导航 |
| `tui_dialogs.go` | 输入框、确认框、错误提示弹窗 |
| `tui_theme.go` | 颜色配色与组件样式 |

---

### 1.3 系统分层

```
┌─────────────────────────────────────────┐
│           TUI（前台进程）                │
│   tui_app / tui_handlers / tui_menus …  │
└─────────────────┬───────────────────────┘
                  │ Unix Socket IPC
┌─────────────────▼───────────────────────┐
│        ControlServer（本地控制 API）     │
│        control_server / control_client  │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│            VPNService（编排层）          │
│  vpn_service / config / service_logger  │
│  ┌──────────┐  ┌──────────┐  ┌───────┐ │
│  │VPNServer │  │VPNClient │  │Cert   │ │
│  │（数据面）│  │（数据面）│  │API    │ │
│  └─────┬────┘  └────┬─────┘  │Server │ │
│        │            │        └───────┘ │
│  ┌─────▼────────────▼──────────────┐   │
│  │     CertificateManager          │   │
│  │     TokenManager                │   │
│  │     IPPool / RouteManager / NAT │   │
│  └─────────────────────────────────┘   │
└─────────────────────────────────────────┘
```

三层职责：

- **编排层**（`vpn_service.go`、`main.go`、`config.go`）：生命周期管理，按序初始化各子系统，统一退出清理。
- **控制面**（`control_*`、`cert_*`、`token_*`、`api_protocol.go`、`protocol_message.go`）：证书 bootstrap、Token 管理、本地 IPC API、TUI 与后台之间的状态同步。
- **数据面**（`vpn_client.go`、`vpn_server.go`、`tun_*`、`route_manager*`、`iptables_nat.go`）：TUN 读写、IP 包封装/转发、路由/NAT 配置。

---

### 1.4 消息协议：固定 5 字节消息头

数据通道不直接传输裸 IP 包，而是封装为 `Message`，以解决 TLS 字节流的分帧问题。

消息头格式（固定 5 字节）：

```
+--------+-------------------+------------------+
| Type   | Length (4B, BE)   | Payload（变长）  |
| 1 byte | 4 bytes big-endian| Length 字节      |
+--------+-------------------+------------------+
```

消息类型包括：`MessageTypeIPAssignment`（服务端下发虚拟 IP）、`MessageTypeControl`（配置 JSON）、`MessageTypeData`（IP 包数据）、`MessageTypeHeartbeat`（心跳保活）等。

> 注：客户端握手时读取的头部为 13 字节（`header := make([]byte, 13)`），其中前 5 字节为 Type+Length，后 8 字节含应用层序列号等扩展字段。

---

### 1.5 运行模型（`main.go`）

#### 命令分发

```go
func main() {
    if len(os.Args) > 1 {
        switch os.Args[1] {
        case "-h", "--help", "help":
            printHelp(); return
        case "--service":
            runServiceDaemon(); return
        case "--stop":
            stopService(); return
        case "--status":
            showStatus(); return
        }
    }
    runSmart()
}
```

#### Smart 启动（默认路径）

`runSmart()` 实现"普通用户无感启动"：

1. 创建 `ControlClient`（IPC 客户端）
2. 若后台未运行 → `startDaemon()` fork 出 `--service` 子进程
3. `waitForService()` 轮询最多 5s 等待后台就绪
4. `runTUI(client)` 启动终端界面

```go
func runSmart() {
    client := NewControlClient()
    if !client.IsServiceRunning() {
        ... startDaemon() ...
        if !waitForService(client, 5*time.Second) { ... }
    }
    runTUI(client)
}
```

#### Daemon 模式（`--service`）

`runServiceDaemon()` 是真正的服务进程：

1. 初始化滚动日志（`NewRotatingFileWriter`）
2. `NewVPNService()` 创建服务实例（加载配置文件）
3. `NewControlServer(service).Start()` 暴露本地控制 API
4. 监听系统信号 → 收到后依次 `service.Cleanup()` + `controlServer.Stop()`

```go
func runServiceDaemon() {
    ...
    service := NewVPNService()
    controlServer := NewControlServer(service)
    if err := controlServer.Start(); err != nil { ... }

    sigChan := setupSignalHandler()
    <-sigChan
    service.Cleanup()
    controlServer.Stop()
}
```

---

### 1.6 VPNService 编排层（`vpn_service.go`）

`VPNService` 是整个系统的领域服务层，核心结构：

```go
type VPNService struct {
    mu          sync.RWMutex
    server      *VPNServer
    client      *VPNClient
    apiServer   *CertAPIServer
    certManager *CertificateManager
    config      VPNConfig
    configFile  string
    certDir     string
    tokenDir    string
}
```

#### 初始化：`NewVPNService()`

- 默认配置来自 `DefaultConfig`
- 尝试 `LoadConfigFromFile(DefaultConfigFile)`，成功则覆盖默认值
- 配置是 daemon 常驻的"单一事实来源"，TUI/CLI 只是修改它

#### 服务端启动序列：`StartServer()`

```go
func (s *VPNService) StartServer() error {
    ... getOrInitCertManager(true) ...     // 自动生成 CA + server cert（如不存在）
    server, err := NewVPNServer(serverAddr, certManager, s.config)
    ... server.InitializeTUN() ...         // 创建 TUN，配置 server IP (.1)，开启 IP 转发
    if s.config.EnableNAT { setupServerNAT(...) }  // 按需配置 iptables
    s.startCertAPIServer(certManager)     // 启动 HTTP 8081
    s.server = server
    go server.Start(context.Background()) // 开始 Accept + session 管理
    return nil
}
```

> `startCertAPIServer()` 依赖 `ca.pem` 和 `ca-key.pem`，因此必须在 `NewCertificateManager()` 生成/保存 CA 之后才能正常启动。

#### 客户端连接：`ConnectClient()`

```go
func (s *VPNService) ConnectClient() error {
    certManager, err := LoadCertificateManagerForClient(s.certDir)
    if err != nil {
        return fmt.Errorf("加载证书失败: %v (请先申请证书)", err)
    }
    client := NewVPNClient(certManager, s.config)
    if err := client.InitializeTUN(); err != nil { ... }
    s.client = client
    go client.Run(context.Background())
    return nil
}
```

无 `client.pem`/`client-key.pem`/`ca.pem` 则报错退出，强制先完成证书申请（bootstrap 流程）。

#### Token 管理：`GenerateToken()` / `GetTokenList()` / `CleanupExpiredTokens()`

`GenerateToken()` 优先复用 `apiServer` 中已有的 `TokenManager`（避免双重加载），否则新建临时实例；生成后将 Token JSON 文件以 0600 权限写入 `tokenDir`，`key_hex` 字段保存 AES key 的十六进制形式。`GetTokenList()` 与 `CleanupExpiredTokens()` 遍历目录中所有 `.json` 文件，按 `used`/`expired` 字段统计状态或删除过期条目。

---

### 1.7 证书体系（`cert_manager.go`）

#### 核心数据结构

```go
type CertificatePair struct {
    Certificate tls.Certificate
    CAPool      *x509.CertPool
}

type CertificateManager struct {
    ServerCert CertificatePair   // 服务端证书 + CA pool（用于验证客户端证书）
    ClientCert CertificatePair   // 客户端证书 + CA pool（用于验证服务端证书）
    caCert     *x509.Certificate
}
```

#### CA 自动生成：`generateCACertificate()`

- RSA 4096，有效期 10 年
- `IsCA=true` + `KeyUsageCertSign`
- EKU 同时包含 `ServerAuth` + `ClientAuth`（便于签发两类证书）
- `ca-key.pem` 以 0400 权限保存

#### 服务端证书生成：`generateCertificatePair(isServer=true)`

- RSA 4096，有效期 1 年
- CN=`vpn-server`，DNSNames 包含 `localhost` 和 `vpn-server`（与客户端 `ServerName` 耦合）
- 实际客户端证书不在此处生成，而是通过 Token+CSR 机制为每个客户端单独签发

#### 强制 TLS 1.3 + mTLS

```go
func (cm *CertificateManager) ServerTLSConfig() *tls.Config {
    return &tls.Config{
        Certificates: []tls.Certificate{cm.ServerCert.Certificate},
        ClientAuth:   tls.RequireAndVerifyClientCert,
        ClientCAs:    cm.ServerCert.CAPool,
        MinVersion:   tls.VersionTLS13,
        MaxVersion:   tls.VersionTLS13,
    }
}

func (cm *CertificateManager) ClientTLSConfig() *tls.Config {
    return &tls.Config{
        Certificates: []tls.Certificate{cm.ClientCert.Certificate},
        RootCAs:      cm.ClientCert.CAPool,
        ServerName:   "vpn-server",  // 必须与服务端 SAN/CN 匹配
        MinVersion:   tls.VersionTLS13,
        MaxVersion:   tls.VersionTLS13,
    }
}
```

---

### 1.8 Token 体系（`token_manager.go` / `token_crypto.go`）

#### Token 结构

```go
type Token struct {
    ID         string    `json:"id"`
    Key        []byte    `json:"-"`            // 不直接序列化；另存为 key_hex
    ClientName string    `json:"client_name"`
    UsedBy     string    `json:"used_by,omitempty"`
    ...
}
```

#### 生成

- 32 字节随机 key（`rand.Read`，即 AES-256 key）
- ID 格式：`<clientName>-<timestamp>`（如 `alice-20240101-120000`）

#### 校验与单次使用：`ValidateAndUseToken()`

```go
if token.Used { return nil, fmt.Errorf("Token已被使用") }
if time.Now().After(token.ExpiresAt) { return nil, fmt.Errorf("Token已过期") }

token.Used = true
token.UsedAt = time.Now()
token.UsedBy = clientIP
tm.saveTokenToFile(token)  // 立即持久化，防止并发重用
```

#### AES-GCM 加密：`EncryptWithToken` / `DecryptWithToken`

Token key 同时充当：
1. **授权凭证**：服务端验证 Token 是否存在、有效、未使用
2. **AES-256-GCM 对称密钥**：端到端加密 CSR 与签发的证书

---

### 1.9 VPN 服务端（`vpn_server.go`）

#### 核心数据结构

```go
type VPNSession struct {
    ID            string
    RemoteAddr    net.Addr
    TLSConn       *tls.Conn
    LastActivity  time.Time
    IP            net.IP
    CertSubject   string     // 客户端证书 CN，供后续扩展绑定 IP
    closed        bool
    mutex         sync.RWMutex
    sendSeq       uint32
    recvSeq       uint32
    seqMutex      sync.Mutex
    BytesSent     uint64
    BytesReceived uint64
    ConnectedAt   time.Time
}

type VPNServer struct {
    listener     net.Listener
    tlsConfig    *tls.Config
    sessions     map[string]*VPNSession
    ipToSession  map[string]*VPNSession  // O(1) 按目的 IP 查找会话
    vpnNetwork   *net.IPNet
    clientIPPool *IPPool
    tunDevice    TUNDevice
    serverIP     net.IP
    natRules     []NATRule
    ...
}
```

`ipToSession` 使从 TUN 读到的包可直接按目的 IP 找到目标客户端会话，支持多客户端互通。

#### TUN 初始化：`InitializeTUN()`

1. `checkRootPrivileges()`（需要 CAP_NET_ADMIN / 管理员权限）
2. `createTUNDevice("tun", s.config.Network)`
3. 配置 server VPN IP 为网段 `.1`（`net.IPv4(base[0], base[1], base[2], 1)`）
4. `configureTUNDevice(tun.Name(), serverIP+"/24", MTU)`（掩码硬编码 /24）
5. `enableIPForwarding()`

> 工程隐患：`/24` 掩码硬编码，若 `config.Network` 为非 /24 的 CIDR 则需同步修改此处及客户端的 `ConfigureTUN()`。

#### 连接处理：`handleConnection()`

安全检查序列：
1. 断言 `*tls.Conn`
2. `Handshake()` 成功
3. `PeerCertificates` 非空（强制 mTLS）
4. 并发连接数 ≤ `MaxConnections`
5. `IPPool.AllocateIP()` 分配虚拟 IP
6. 发送 `Message(IPAssignment)` → 客户端获得 IP
7. 发送 `Message(Control, JSON)` → 客户端获得路由/DNS 配置
8. 启动 `go handleSessionData(ctx, session)`

#### 主循环：`Start(ctx)`

```go
go s.handleTUNRead(ctx)   // server TUN → 按目的 IP 转发至客户端
go s.cleanupSessions(ctx) // 按 SessionTimeout 定时清理超时会话
for {
    conn, _ := s.listener.Accept()
    go s.handleConnection(ctx, conn)
}
```

---

### 1.10 VPN 客户端（`vpn_client.go`）

#### 核心字段

```go
type VPNClient struct {
    tlsConfig    *tls.Config  // 含 client cert
    conn         *tls.Conn
    assignedIP   net.IP       // 服务端下发
    reconnect    int32        // atomic 控制重连开关
    tunDevice    TUNDevice
    sendSeq      uint32
    recvSeq      uint32
    routeManager *RouteManager
    retryCount   int
    ...
}
```

#### 连接握手状态机：`Connect(ctx)`

1. TCP Dial（30s timeout）
2. `tls.Client(netConn, c.tlsConfig)` + `Handshake()`
3. 强制检查 `ConnectionState().Version == tls.VersionTLS13`
4. 读取第一条消息（13 字节头）：`MessageTypeIPAssignment` → `c.assignedIP`
5. 读取第二条消息：`MessageTypeControl` → JSON 解析 `ClientConfig` → 合并路由/DNS 配置

#### 运行主循环：`Run(ctx)`（连接-会话-断线-重连状态机）

```
while reconnect == 1:
    Connect 失败 → 计数 + sleep(backoff)，可被 ctx 中断
    Connect 成功 →
        ConfigureTUN(assignedIP/24)
        setupRoutes(full/split)
        sessionCtx = context.WithCancel(ctx)
        go startHeartbeat(sessionCtx)
        go handleTUNRead(sessionCtx)  // TUN → TLS（出站）
        dataLoop(sessionCtx)          // TLS → TUN（入站）
        cancel(sessionCtx) + closeConnection
        等待后重连
```

数据路径：
- **出站**：`TUN.Read` → `SendData` → `TLS.Write(Message(Data))`
- **入站**：`TLS.Read(Message)` → `ReceiveData` → `TUN.Write`

---

### 1.11 端到端数据流时序图

#### 证书申请（HTTP 8081）

```
Client              VPNService            CertAPIServer       TokenManager   CA
  |                     |                      |                   |          |
  | GenerateCSR()        |                      |                   |          |
  | rsa.GenerateKey(4096)|                      |                   |          |
  | 生成 .csr + -key.pem |                      |                   |          |
  |                     |                      |                   |          |
  | RequestCert(token,csr)                      |                   |          |
  |-------------------->|                      |                   |          |
  |                     | EncryptWithToken(CSR) |                   |          |
  |                     | POST /api/cert/request|                   |          |
  |                     |--------------------->|                   |          |
  |                     |                      | ValidateAndUseToken           |
  |                     |                      |------------------>| mark used |
  |                     |                      |                   |  + save   |
  |                     |                      | SignCertificate(CSR)          |
  |                     |                      |---------------------------------------->|
  |                     |                      | EncryptWithToken(cert + ca)             |
  |                     |<---------------------|                   |          |
  |                     | DecryptWithToken      |                   |          |
  |                     | 保存 ca.pem / client.pem / client-key.pem             |
  |<--------------------|                      |                   |          |
```

#### VPN 数据通道建立（TCP/TLS 8080）

```
VPNClient                                        VPNServer
    |                                                |
    | tls.Dial + Handshake (TLS 1.3 + mTLS)         |
    |----------------------------------------------->|
    |                                                | 校验 PeerCertificates
    |                                                | AllocateIP() → assignedIP
    |                                                | send Message(IPAssignment)
    |<-----------------------------------------------|
    | c.assignedIP = payload                         |
    |                                                | send Message(Control, JSON)
    |<-----------------------------------------------|
    | 解析 ClientConfig（routes/dns/route_mode）     |
    | ConfigureTUN(assignedIP/24)                    |
    | setupRoutes(full/split)                        |
    | go startHeartbeat()                            |
    | go handleTUNRead() ← TUN→TLS 出站             |
    | dataLoop()         ← TLS→TUN 入站             |
```

#### 服务端多客户端转发

```
                      VPNServer
          ┌────────────────────────────────────┐
          │  sessions[id]    = VPNSession      │
          │  ipToSession[ip] = VPNSession      │  ← O(1) 按目的 IP 查找
          └──────────────────┬─────────────────┘
                             │
                  go handleTUNRead(ctx)
                             │
                  从 server TUN 读取 IP 包
                  destIP = pkt[16:20]（IPv4 目的地址）
                             │
                  ipToSession[destIP] → VPNSession
                             │
                  session.TLSConn.Write(Message(Data))
```

---

### 1.12 安全性与工程设计要点

**TLS 1.3 强制 + 降级防护**：`ServerTLSConfig()` 与 `ClientTLSConfig()` 均设 `MinVersion = MaxVersion = tls.VersionTLS13`，杜绝协议降级攻击。

**mTLS 双向验证**：服务端 `RequireAndVerifyClientCert` + 握手后显式检查 `PeerCertificates`，客户端无证书时连接即被拒绝。

**私钥不出本机**：`GenerateCSR()` 在客户端本地生成 RSA 4096 私钥（写入 0600 权限文件），仅 CSR 经网络传输，符合 PKI 最佳实践。

**Token 单次使用**：`ValidateAndUseToken()` 校验通过后立即标记 `used=true` 并持久化，防止重放攻击。Token key 在证书落盘后即失去进一步价值。

**证书 API 明文传输风险**：`RequestCert()` 向 HTTP 8081 POST，payload 由 AES-GCM 加密保证机密性，但 TLS 握手元数据仍可见；建议对 8081 端口做来源 IP 限制。

**`ServerName` 硬耦合**：客户端 `ServerName: "vpn-server"` 与服务端证书 DNSNames `vpn-server` 强耦合，是系统部署的关键配置点。

**资源清理**：路由、iptables、TUN、IP 租约均为系统全局状态，`VPNService.Cleanup()` 在 `signal_*` 捕获退出信号后负责全部回滚。

**掩码硬编码（技术债）**：TUN 配置中掩码固定为 `/24`，若 `config.Network` 为非 /24 的 CIDR，服务端与客户端均需同步修改。

**跨平台隔离**：`tun_device_unix.go` / `tun_device_windows.go`、`route_manager.go` / `route_manager_windows.go`、`daemon_unix.go` / `daemon_windows.go` 各自封装平台差异，上层代码通过接口统一调用，利用 Go 文件名后缀实现编译期隔离。

---

## 第二章 控制面与协议框架

本章详细介绍 TLS-VPN 控制面的三个核心组成部分：应用层消息协议（framing 层）、Token 加密层（bootstrap 安全通道），以及证书 API Server（信任入口）。

---

### 2.1 应用层消息协议（`protocol_message.go`）

#### 2.1.1 协议目标与定位

尽管底层已使用 TLS 1.3（AEAD 保障机密性与完整性），项目仍实现了一个应用层 framing 协议，原因在于：TLS 连接是字节流，接收端无法从中直接判断每条应用消息的边界，必须通过 length prefix 解决"粘包/分包"问题。

#### 2.1.2 消息格式（固定 5 字节头）

```
+--------+---------------------------+-----------------+
| Type   | Length（4B, big-endian）  | Payload（变长） |
| 1 byte | 4 bytes                   | Length 字节     |
+--------+---------------------------+-----------------+
```

源码定义：

```go
type MessageType uint8

const (
    MessageTypeData        MessageType = iota // IP 包数据
    MessageTypeHeartbeat                      // 心跳保活
    MessageTypeIPAssignment                   // 服务端下发虚拟 IP
    MessageTypeAuth                           // 保留扩展
    MessageTypeControl                        // 配置 JSON 推送
)

type Message struct {
    Type     MessageType
    Length   uint32
    Sequence uint32 // 应用层序列号（用于重放检测）
    Checksum uint32 // CRC32 校验（0 表示不校验）
    Payload  []byte
}
```

#### 2.1.3 序列化与反序列化

**序列化**（`Serialize()`）：仅拼包，不计算 Checksum；Checksum 由调用层（如 `sendDataResponse`）按需填写。

```go
func (m *Message) Serialize() ([]byte, error) {
    if m.Length != uint32(len(m.Payload)) {
        m.Length = uint32(len(m.Payload))
    }
    header := make([]byte, SimpleHeaderSize) // 5 字节
    header[0] = byte(m.Type)
    binary.BigEndian.PutUint32(header[1:5], m.Length)
    return append(header, m.Payload...), nil
}
```

**反序列化**（`Deserialize()`）：检查数据长度是否满足头部要求，再取 payload。

```go
func Deserialize(data []byte) (*Message, error) {
    if len(data) < SimpleHeaderSize {
        return nil, fmt.Errorf("消息长度不足")
    }
    msgType := MessageType(data[0])
    length := binary.BigEndian.Uint32(data[1:5])
    if uint32(len(data)) < SimpleHeaderSize+length {
        return nil, fmt.Errorf("消息长度不匹配")
    }
    payload := data[SimpleHeaderSize : SimpleHeaderSize+length]
    return &Message{Type: msgType, Length: length, Payload: payload}, nil
}
```

> 注：`MessageTypeAuth` 当前未在主链路中使用（主链路依赖 mTLS 证书鉴权），作为扩展接口保留，可用于未来实现"证书 CN + Token 绑定校验"或"二次认证因子"等场景。

#### 2.1.4 控制消息载荷：`ClientConfig`

`MessageTypeControl` 消息的 payload 为 JSON，服务端在连接建立时将以下结构体推送给客户端：

```go
type ClientConfig struct {
    AssignedIP      string   `json:"assigned_ip"`      // 分配的 IP 地址，如 "10.8.0.2/24"
    ServerIP        string   `json:"server_ip"`        // 服务器 IP 地址
    DNS             []string `json:"dns"`              // DNS 服务器列表
    Routes          []string `json:"routes"`           // 路由列表（CIDR 格式）
    MTU             int      `json:"mtu"`              // MTU 大小
    RouteMode       string   `json:"route_mode"`       // "full"（全局）或 "split"（分流）
    ExcludeRoutes   []string `json:"exclude_routes"`   // 全局模式下排除的路由
    RedirectGateway bool     `json:"redirect_gateway"` // 是否重定向默认网关
    RedirectDNS     bool     `json:"redirect_dns"`     // 是否接管 DNS
}
```

客户端在握手后接收第二条消息（`MessageTypeControl`）时，解析此结构体并将路由/DNS 配置合并进运行态。

---

### 2.2 Token 加密层（`token_crypto.go`）

该模块实现证书申请通道的端到端加密，保证即便证书 API 走明文 HTTP（端口 8081），中间人也只能看到密文。

#### 2.2.1 请求/响应结构

```go
// 客户端发送的加密证书请求
type EncryptedCertRequest struct {
    TokenID      string `json:"token_id"`
    EncryptedCSR []byte `json:"encrypted_csr"` // AES-GCM 密文，JSON 中自动 base64 编码
    Nonce        []byte `json:"nonce"`
}

// 服务端返回的加密证书响应
type EncryptedCertResponse struct {
    Success       bool   `json:"success"`
    EncryptedCert []byte `json:"encrypted_cert,omitempty"`
    EncryptedCA   []byte `json:"encrypted_ca,omitempty"`
    Nonce         []byte `json:"nonce,omitempty"`
    CANonce       []byte `json:"ca_nonce,omitempty"`
    Error         string `json:"error,omitempty"`
}
```

> `[]byte` 字段在 Go 的 `encoding/json` 中会自动编码为 base64 字符串，wire format 为 JSON + base64，对 HTTP API 友好。

#### 2.2.2 加密：`EncryptWithToken()`（AES-256-GCM）

- `tokenKey` 直接作为 AES key，要求严格为 32 字节（由上层 `RequestCert` 在调用前强校验）
- GCM 随机生成 nonce（`gcm.NonceSize()`，通常 12 字节）
- AAD 为空（`gcm.Seal(nil, nonce, data, nil)`）

```go
func EncryptWithToken(data []byte, tokenKey []byte) (ciphertext, nonce []byte, err error) {
    block, err := aes.NewCipher(tokenKey)
    if err != nil {
        return nil, nil, fmt.Errorf("创建cipher失败: %v", err)
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, nil, fmt.Errorf("创建GCM失败: %v", err)
    }
    nonce = make([]byte, gcm.NonceSize())
    if _, err := rand.Read(nonce); err != nil {
        return nil, nil, fmt.Errorf("生成nonce失败: %v", err)
    }
    ciphertext = gcm.Seal(nil, nonce, data, nil)
    return ciphertext, nonce, nil
}
```

#### 2.2.3 解密：`DecryptWithToken()`

认证标签验证失败（即密文被篡改或 key 错误）时，`gcm.Open` 返回错误，函数向上层传递"数据被篡改"提示。

```go
func DecryptWithToken(ciphertext, nonce, tokenKey []byte) ([]byte, error) {
    block, err := aes.NewCipher(tokenKey)
    if err != nil {
        return nil, fmt.Errorf("创建cipher失败: %v", err)
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, fmt.Errorf("创建GCM失败: %v", err)
    }
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return nil, fmt.Errorf("解密失败或数据被篡改: %v", err)
    }
    return plaintext, nil
}
```

---

### 2.3 证书 API Server（`cert_api_server.go`）

`CertAPIServer` 是整个系统 bootstrap 的信任入口，监听 HTTP 8081，提供证书申请接口。

#### 2.3.1 结构体与初始化

```go
type CertAPIServer struct {
    tokenManager *TokenManager
    certManager  *CertificateManager
    caCert       *x509.Certificate
    caKey        *rsa.PrivateKey
    port         int
    server       *http.Server
}
```

构造函数 `NewCertAPIServer()` 从 `DefaultTokenDir`（`./tokens`）加载已有 Token：

```go
func NewCertAPIServer(port int, certManager *CertificateManager, caCert *x509.Certificate, caKey *rsa.PrivateKey) *CertAPIServer {
    return &CertAPIServer{
        tokenManager: NewTokenManagerWithLoad(DefaultTokenDir),
        certManager:  certManager,
        caCert:       caCert,
        caKey:        caKey,
        port:         port,
    }
}
```

`Start()` 注册两个 endpoint 并启动 HTTP server：

```go
mux.HandleFunc("/api/cert/request", api.handleCertRequest) // 核心：申请证书
mux.HandleFunc("/api/health", api.handleHealth)            // 探活
```

#### 2.3.2 证书请求处理：`handleCertRequest()`

完整处理管线按以下顺序执行：

**(1) 方法校验 + 获取 clientIP（支持 X-Forwarded-For）**

```go
if r.Method != http.MethodPost {
    http.Error(w, "只支持POST请求", http.StatusMethodNotAllowed)
    return
}
clientIP := r.RemoteAddr
if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
    clientIP = forwarded
}
```

**(2) 解析请求体 + 校验并使用 Token**

```go
var req EncryptedCertRequest
if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
    api.sendError(w, "解析请求失败: "+err.Error(), http.StatusBadRequest)
    return
}

token, err := api.tokenManager.ValidateAndUseToken(req.TokenID, clientIP)
if err != nil {
    // Token 不存在 / 已过期 / 已使用 → 拒绝
}
```

`ValidateAndUseToken` 一旦成功即将 Token 标记为已使用，天然防止重放攻击。

**(3) 解密 CSR → 解析 → 签发证书**

```go
// DecryptWithToken(req.EncryptedCSR, req.Nonce, token.Key) → csrPEM
// pem.Decode → x509.ParseCertificateRequest → api.signCertificate(csr)
```

`signCertificate()` 使用 CA 私钥签发证书，模板包含：NotBefore/NotAfter、`ExtKeyUsageClientAuth`、证书序列号等。

**(4) 加密客户端证书与 CA 证书后返回**

```go
encryptedCert, nonce, err := EncryptWithToken(certPEM, token.Key)

caCertPEM, err := os.ReadFile(DefaultCertDir + "/ca.pem")
encryptedCA, caNonce, err := EncryptWithToken(caCertPEM, token.Key)

resp := EncryptedCertResponse{
    Success:       true,
    EncryptedCert: encryptedCert,
    EncryptedCA:   encryptedCA,
    Nonce:         nonce,
    CANonce:       caNonce,
}
json.NewEncoder(w).Encode(resp)
```

CA 证书随客户端证书一并下发，客户端无需单独获取即可完成完整的信任链配置。

#### 2.3.3 请求处理错误分支

```
POST /api/cert/request
  │
  ├─ Method ≠ POST ──────────────────────────────→ 405
  │
  ├─ JSON decode 失败 ────────────────────────────→ 400
  │
  ├─ ValidateAndUseToken 失败 ────────────────────→ 401/400
  │     ├─ Token 不存在
  │     ├─ Token 已过期
  │     └─ Token 已被使用
  │
  ├─ DecryptWithToken(CSR) 失败 ──────────────────→ 400
  │     ├─ nonce 长度不匹配
  │     └─ GCM 认证标签验证失败（密文被篡改/Key 错误）
  │
  ├─ PEM/CSR 解析失败 ────────────────────────────→ 400
  │
  ├─ CSR 签名验证失败 ────────────────────────────→ 400
  │
  ├─ 证书签发失败 ────────────────────────────────→ 500
  │
  ├─ 加密证书/CA 失败 ────────────────────────────→ 500
  │
  └─ 成功 ────────────────────────────────────────→ 200
       { success: true, encrypted_cert, encrypted_ca, nonce, ca_nonce }
```

---

### 2.4 证书申请通道的安全分析

**明文 HTTP 的合理性**：`RequestCert()` 通过 HTTP 向 8081 端口 POST，payload 由 AES-256-GCM 加密保证机密性与完整性。中间人即使截获请求，也无法在不持有 Token key 的情况下解密 CSR 或伪造证书。建议在生产环境中对 8081 端口设置来源 IP 白名单，进一步限制攻击面。

**Token key 的双重用途**：Token 的 32 字节随机 key 同时承担两个角色：
1. **授权凭证**：服务端通过 `ValidateAndUseToken` 验证 Token 是否存在、有效、未使用
2. **端到端对称密钥**：AES-256-GCM 加密 CSR（上行）和证书+CA（下行）

**单次使用设计**：Token 一旦验证成功即标记为 `used=true` 并持久化，从根本上杜绝重放攻击。证书落盘后 Token key 不再具有操作意义，即便泄露也无法危害已建立的 mTLS 通道。

---

## 第三章 网络系统实现与日志基础

本章深入介绍 TLS-VPN 数据面的底层实现：TUN 虚拟网卡的跨平台创建与读写、IP 地址池的分配回收、路由/DNS 接管与回滚，以及 iptables NAT 配置。章节最后介绍日志子系统的设计（轮转文件写入 + 内存序列化缓冲）。

---

### 3.1 TUN 虚拟网卡（`tun_interface.go` / `tun_device_unix.go` / `tun_device_windows.go`）

#### 3.1.1 跨平台抽象接口

`tun_interface.go` 定义 `TUNDevice` 接口，屏蔽平台差异，使 `vpn_client`/`vpn_server` 只依赖抽象：

```go
type TUNDevice interface {
    ReadPacket(buf []byte) (int, error)   // 从 TUN 读取一个 IP 包
    WritePacket(buf []byte) (int, error)  // 向 TUN 写入一个 IP 包
    Close() error                          // 关闭设备
    Name() string                          // 返回接口名（如 "tun0"）
}
```

读写均为阻塞 I/O，调用方需在独立 goroutine 中运行，并通过 `context.Done()` 或关闭设备句柄来中断阻塞。

#### 3.1.2 Unix/Linux 实现（`tun_device_unix.go`）

Unix 下 TUN 设备的创建与配置分两个阶段：

**阶段 1：创建设备**

```go
func createTUNDevice(name string, network string) (TUNDevice, error) {
    // 1. 打开 /dev/net/tun
    fd, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
    // 2. 通过 ioctl(TUNSETIFF) 注册设备名与 IFF_TUN 标志
    ifr := ... // struct ifreq: 设备名 + IFF_TUN | IFF_NO_PI
    syscall.Syscall(syscall.SYS_IOCTL, fd.Fd(), syscall.TUNSETIFF, ...)
    // 3. 返回封装了 fd 的 TUNDevice 实现
}
```

- `IFF_TUN`：三层模式（收发 IP 包，无以太网帧头）
- `IFF_NO_PI`：不在包前附加 4 字节 protocol info，读到的就是原始 IP 包

**阶段 2：配置地址与 MTU**

```go
func configureTUNDevice(ifaceName, ipCIDR string, mtu int) error {
    // ip link set dev <ifaceName> up
    exec.Command("ip", "link", "set", "dev", ifaceName, "up").Run()
    // ip addr add <ipCIDR> dev <ifaceName>
    exec.Command("ip", "addr", "add", ipCIDR, "dev", ifaceName).Run()
    // ip link set dev <ifaceName> mtu <mtu>
    exec.Command("ip", "link", "set", "dev", ifaceName, "mtu",
        strconv.Itoa(mtu)).Run()
}
```

**清理**：

```go
func cleanupTUNDevice(ifaceName string) {
    // TUN 设备在 fd.Close() 后由内核自动删除
    // 此处仅将接口 down（保险措施）
    exec.Command("ip", "link", "set", "dev", ifaceName, "down").Run()
}
```

#### 3.1.3 Windows 实现（`tun_device_windows.go`）

Windows 下基于 **Wintun** 驱动，通过 ring buffer 实现高性能零拷贝读写：

```go
func createTUNDevice(name string, network string) (TUNDevice, error) {
    // 1. 加载 Wintun DLL / 调用 WintunOpenAdapter 或 WintunCreateAdapter
    // 2. WintunStartSession 启动会话，获取 ring buffer 句柄
    // 3. 用 netsh 配置 IP 地址与路由
    //    netsh interface ip set address <name> static <ip> <mask>
}

func cleanupTUNDevice(ifaceName string) {
    // Wintun 设备在 session.End() + adapter.Close() 时自动清理
    // 无需额外命令
}
```

> Windows 实现依赖 Wintun 驱动已安装，ring buffer 读写绕过内核协议栈，延迟与吞吐均优于传统 TAP 设备。

#### 3.1.4 TUN 读写的并发模型

数据面使用两个独立 goroutine 实现全双工转发：

```
goroutine handleTUNRead(ctx):
    loop:
        select ctx.Done → return
        n, err = tun.ReadPacket(buf)
        if err → return（设备关闭时 Read 立即返回错误）
        SendData(conn, buf[:n])  // 封帧 → TLS.Write

goroutine dataLoop(ctx):
    loop:
        msg = ReceiveData(conn)  // TLS.Read → 解帧
        if err → break
        tun.WritePacket(msg.Payload)
```

关闭顺序设计为：先 `cancel(ctx)` 触发 `ctx.Done`，再 `tun.Close()` 强制打断仍在阻塞 `ReadPacket` 的 goroutine，实现双保险退出。

---

### 3.2 IP 地址池（`ip_pool.go`）

#### 3.2.1 设计目标

`IPPool` 负责 VPN 网段内客户端虚拟 IP 的分配与回收，保证多客户端并发连接时地址不冲突，断线时地址能被复用。

#### 3.2.2 初始化

```go
func NewIPPool(network *net.IPNet, config *VPNConfig) *IPPool {
    // 遍历网段内所有地址，排除：
    //   - 网络地址（如 10.8.0.0）
    //   - 广播地址（如 10.8.0.255）
    //   - 服务端自身地址（.1）
    // 将剩余地址加入可用队列
}
```

#### 3.2.3 分配与回收

```go
func (p *IPPool) AllocateIP() (net.IP, error) {
    p.mu.Lock()
    defer p.mu.Unlock()
    // 从可用队列取一个地址，标记为 inUse
    // 若队列为空，返回 "地址池已满" 错误
}

func (p *IPPool) ReleaseIP(ip net.IP) {
    p.mu.Lock()
    defer p.mu.Unlock()
    // 将地址从 inUse 移回可用队列
}
```

两种常见实现方式：
- **slice + map**：`available []net.IP` 队列 + `inUse map[string]bool`，简单直观
- **channel 队列**：`available chan net.IP`，天然并发安全，无需手动加锁

#### 3.2.4 与会话生命周期的绑定

`AllocateIP` 在 `VPNServer.handleConnection()` 中握手成功后调用；`ReleaseIP` 在 `removeSession()` 内、持有 `sessionMutex` 时调用，确保 IP 回收与会话 map 删除的原子性：

```go
func (s *VPNServer) removeSession(id string) {
    s.sessionMutex.Lock()
    session, exists := s.sessions[id]
    if exists {
        s.clientIPPool.ReleaseIP(session.IP)  // 先回收 IP
        delete(s.sessions, id)
        delete(s.ipToSession, session.IP.String())
        s.sessionCount--
    }
    s.sessionMutex.Unlock()

    if exists && session != nil {
        _ = session.Close()  // 锁外关闭连接（避免持锁做网络 IO）
    }
}
```

---

### 3.3 路由管理（`route_manager.go` / `route_manager_windows.go`）

#### 3.3.1 职责概述

`RouteManager` 负责客户端侧的路由与 DNS 接管，采用**"记录变更 → 退出回滚"**模型，保证 VPN 断开后宿主网络恢复原状。

核心字段：

```go
type RouteManager struct {
    mutex          sync.Mutex
    installedRoutes []RouteEntry  // 记录本次会话安装的所有路由
    originalDNS    []string       // 记录接管前的 DNS 服务器（用于日志）
    tunInterface   string         // TUN 接口名
}
```

#### 3.3.2 路由模式：full 与 split

客户端连接时，根据 `ClientConfig.RouteMode` 决定策略：

| 模式 | 说明 |
|------|------|
| `full` | 将默认路由（0.0.0.0/0）指向 TUN，所有流量走 VPN；`ExcludeRoutes` 中的网段保持走原网关 |
| `split` | 仅将 `Routes` 中指定的网段指向 TUN，其余流量走原网关 |

#### 3.3.3 路由安装与记录

```go
func (rm *RouteManager) AddRoute(destination, gateway, iface string) error {
    rm.mutex.Lock()
    defer rm.mutex.Unlock()

    // Unix：ip route add <destination> dev <iface>
    //       或 ip route add <destination> via <gateway>
    output, err := runCmdCombined("ip", "route", "add", destination, "dev", iface)
    if err != nil {
        log.Printf("添加路由失败: %v, 输出: %s", err, output)
        // 即便失败，仍记录（退出时尝试删除，幂等）
    }
    rm.installedRoutes = append(rm.installedRoutes, RouteEntry{
        Destination: destination,
        Interface:   iface,
    })
    return err
}
```

#### 3.3.4 路由清理（退出回滚）

```go
func (rm *RouteManager) CleanupRoutes() {
    rm.mutex.Lock()
    defer rm.mutex.Unlock()

    for _, route := range rm.installedRoutes {
        output, err := runCmdCombined("ip", "route", "del", route.Destination)
        if err != nil {
            log.Printf("警告：删除路由 %s 失败: %v, 输出: %s",
                route.Destination, err, output)
        } else {
            log.Printf("已清理路由: %s", route.Destination)
        }
    }
    rm.installedRoutes = make([]RouteEntry, 0)
}
```

#### 3.3.5 DNS 接管与恢复（Unix）

DNS 接管采用**恢复点文件**策略：

```go
// 接管前：备份原始 resolv.conf
func (rm *RouteManager) SaveDNS() error {
    data, err := os.ReadFile("/etc/resolv.conf")
    os.WriteFile("/etc/resolv.conf.vpn-backup", data, 0644)
    // 解析 nameserver 行记录到 rm.originalDNS（供日志）
    return err
}

// 接管：写入 VPN DNS
func (rm *RouteManager) SetDNSForInterface(servers []string) error {
    content := ""
    for _, s := range servers {
        content += "nameserver " + s + "
"
    }
    return os.WriteFile("/etc/resolv.conf", []byte(content), 0644)
}

// 退出时恢复
func (rm *RouteManager) RestoreDNS() error {
    if _, err := os.Stat("/etc/resolv.conf.vpn-backup"); os.IsNotExist(err) {
        log.Println("没有找到DNS备份文件，跳过恢复")
        return nil  // 安全阀：无备份则不写，避免破坏系统 DNS
    }
    data, _ := os.ReadFile("/etc/resolv.conf.vpn-backup")
    os.WriteFile("/etc/resolv.conf", data, 0644)
    os.Remove("/etc/resolv.conf.vpn-backup")  // 删除备份，防止下次误用陈旧备份
    return nil
}
```

#### 3.3.6 Windows 路由管理（`route_manager_windows.go`）

Windows 下使用 `route ADD` / `route DELETE` 命令，或调用 IP Helper API（`netsh interface ipv4 add/delete route`）。DNS 接管则通过 `netsh interface ip set dns` 实现，恢复时同样先备份再还原。

---

### 3.4 NAT 与 IP 转发（`iptables_nat.go`）

#### 3.4.1 功能定位

当 `config.EnableNAT = true` 时，服务端在启动 VPN 后配置 Linux iptables，使 VPN 客户端的流量能经由服务端出口网卡访问外网（或服务端内网）。

#### 3.4.2 开启 IP 转发

NAT 生效的前提是内核 IP 转发已开启：

```go
func enableIPForwarding() error {
    return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644)
}
```

#### 3.4.3 NAT 规则安装

```go
type NATRule struct {
    Table string   // 如 "nat"、"filter"
    Chain string   // 如 "POSTROUTING"、"FORWARD"
    Args  []string // iptables 其余参数
}

func setupServerNAT(vpnCIDR, outIface string) ([]NATRule, error) {
    rules := []NATRule{
        // MASQUERADE：VPN 网段出站时替换源 IP 为出口网卡地址
        {Table: "nat", Chain: "POSTROUTING",
            Args: []string{"-s", vpnCIDR, "-o", outIface, "-j", "MASQUERADE"}},
        // FORWARD：允许 TUN → 出口网卡 方向转发
        {Table: "filter", Chain: "FORWARD",
            Args: []string{"-i", tunIface, "-o", outIface, "-j", "ACCEPT"}},
        // FORWARD：允许已建立连接的反向流量
        {Table: "filter", Chain: "FORWARD",
            Args: []string{"-i", outIface, "-o", tunIface,
                "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"}},
    }
    for _, rule := range rules {
        args := append([]string{"-t", rule.Table, "-A", rule.Chain}, rule.Args...)
        runCmdCombined("iptables", args...)
    }
    return rules, nil
}
```

`VPNServer` 将安装的规则存入 `s.natRules []NATRule`，供退出时清理。

#### 3.4.4 NAT 规则清理

```go
func (s *VPNServer) cleanupNATRules() {
    s.sessionMutex.Lock()
    rules := make([]NATRule, len(s.natRules))
    copy(rules, s.natRules)
    s.natRules = nil          // 立即清空共享列表，避免并发重复清理
    s.sessionMutex.Unlock()

    for _, rule := range rules {
        args := append([]string{"-t", rule.Table, "-D", rule.Chain}, rule.Args...)
        output, err := runCmdCombined("iptables", args...)
        if err != nil {
            log.Printf("警告：删除NAT规则失败: %v (参数: %v), 输出: %s",
                err, args, output)
        } else {
            log.Printf("已删除NAT规则: %v", args)
        }
    }
}
```

清理策略：
- 锁内复制规则列表并清空 `natRules`（防并发重复清理）
- 锁外逐条执行 `iptables -D`（网络命令可能阻塞，不持锁执行）
- 清理失败仅打 warning，不阻断退出流程

---

### 3.5 日志子系统（`service_logger.go`）

#### 3.5.1 设计目标

后台 daemon 需要同时满足两个需求：
1. **持久化**：日志写入文件，供运维留存与离线排查
2. **实时拉取**：TUI 通过 IPC `LogFetch` 增量拉取日志展示，不必读文件

为此，日志系统由两个组件组成：**RotatingFileWriter**（文件轮转写入）和 **ServiceLogBuffer**（内存序列化缓冲）。

#### 3.5.2 RotatingFileWriter（日志文件轮转）

```go
type RotatingFileWriter struct {
    path       string    // 日志文件路径（如 /var/log/tls-vpn/service.log）
    maxSize    int64     // 单文件最大字节数（默认 10MB）
    maxBackups int       // 保留备份数量（默认 5 个，即 .1 ~ .5）
    file       *os.File
    mu         sync.Mutex
}

func NewRotatingFileWriter(path string, maxSizeMB, maxBackups int) (*RotatingFileWriter, error)
```

轮转逻辑：当当前日志文件大小超过 `maxSize` 时，将 `.log` 重命名为 `.log.1`，依此类推（`.1` → `.2` ... `.4` → `.5`，超过 `maxBackups` 的最旧备份被删除），然后创建新文件。

#### 3.5.3 ServiceLogBuffer（内存序列化缓冲）

```go
type LogEntry struct {
    Seq     int64  `json:"seq"`     // 单调递增序列号（游标）
    Time    int64  `json:"time"`    // Unix 毫秒时间戳
    Level   string `json:"level"`   // "INFO" / "WARN" / "ERROR"
    Message string `json:"message"`
}

type ServiceLogBuffer struct {
    mu      sync.RWMutex
    entries []LogEntry
    nextSeq int64
    maxSize int  // 内存中最多保留的条目数（超出则滚动丢弃最旧）
}
```

TUI 通过 `LogFetch(lastSeq int64, limit int)` 增量拉取：

```go
// IPC 请求：LogFetch(lastSeq=100, limit=50)
// 返回：seq > 100 的最多 50 条日志 + 当前 lastSeq
resp, err := t.client.LogFetch(t.lastLogSeq, 50)
for _, entry := range resp.Logs {
    logTime := time.UnixMilli(entry.Time).Format("15:04:05")
    t.logBuffer.AddLineRaw(formatLogLine(entry.Level, entry.Message, logTime))
}
if resp.LastSeq > t.lastLogSeq {
    t.lastLogSeq = resp.LastSeq
}
```

TUI 每 500ms ticker 触发一次 `fetchServiceLogs()`，实现类似 `tail -f` 的实时日志显示效果。

#### 3.5.4 日志初始化流程（daemon 启动时）

```go
// 1. 创建文件轮转 writer（失败则回退到 stdout）
logWriter, err := NewRotatingFileWriter(DefaultLogPath, 10, 5)

// 2. 初始化内存 ServiceLogBuffer，并与 logWriter 组合
logger := InitServiceLogger(logWriter)

// 3. 将 Go 标准库 log 的输出重定向到 logger
log.SetOutput(logger)
log.SetFlags(log.Ldate | log.Ltime)

log.Printf("TLS VPN 服务启动 (PID: %d)", os.Getpid())
```

`InitServiceLogger` 返回一个实现了 `io.Writer` 的对象：每次 `Write` 调用时，既写入 `logWriter`（文件），又解析写入 `ServiceLogBuffer`（内存），实现**双通道并行写入**。

#### 3.5.5 日志设计要点

**游标模型的优势**：TUI 使用 `lastSeq` 游标而非文件偏移量，无需监听文件变化事件，也不存在文件轮转时偏移量失效的问题，简单且跨平台。

**内存上限**：`ServiceLogBuffer` 设有 `maxSize` 上限，超出时滚动丢弃最旧条目，防止长期运行后内存膨胀。

**标准库兼容**：通过 `log.SetOutput(logger)` 将整个程序的 `log.Printf/log.Println` 统一汇入日志系统，无需修改各模块的日志调用。

---

### 3.6 网络系统资源清理总览

本章涉及的四类系统资源均在退出时进行清理，按调用链汇总如下：

| 资源 | 安装时机 | 清理时机 | 清理方法 |
|------|---------|---------|---------|
| TUN 设备 | `InitializeTUN()` | `VPNServer.Stop()` / `VPNClient.Close()` | `tunDevice.Close()` + `cleanupTUNDevice()` |
| 路由条目 | `setupRoutes()` 中 `AddRoute()` | `VPNClient.Close()` | `RouteManager.CleanupRoutes()` |
| DNS 配置 | `SetDNSForInterface()` | `VPNClient.Close()` | `RouteManager.RestoreDNS()` |
| NAT 规则 | `setupServerNAT()` | `VPNServer.Stop()` | `VPNServer.cleanupNATRules()` |

---

## 第四章 端到端运行链路与阶段总结

本章以"一次完整 VPN 会话"为主线，将前三章的模块实现串联为可追踪的执行路径。按时间顺序分为五个阶段：服务端启动、客户端 bootstrap（证书申请）、客户端连接建立、数据包穿透、以及连接维护。章节末尾给出各阶段的关键函数调用链，可作为源码阅读的索引。

---

### 4.1 阶段一：服务端启动

**触发点**：用户执行 `./tls-vpn --service` 或由 Smart 启动模式自动 fork。

```
runServiceDaemon()
    │
    ├── NewRotatingFileWriter(DefaultLogPath, 10, 5)
    │       └── 创建日志文件，设置轮转策略（10MB/文件，5 个备份）
    │
    ├── InitServiceLogger(logWriter)
    │       └── 双通道写入：文件 + 内存 ServiceLogBuffer（seq 游标）
    │
    ├── log.SetOutput(logger)         ← 标准库 log 统一汇入
    │
    ├── NewVPNService()
    │       ├── DefaultConfig         ← 内建默认值
    │       └── LoadConfigFromFile()  ← 加载 config.json（若存在则覆盖）
    │
    └── NewControlServer(service).Start()
            └── 监听 Unix Socket（本地 IPC），等待 TUI/CLI 控制命令
```

此时 daemon 已就绪，但 VPN 数据面（`VPNServer`）尚未启动。数据面由后续 IPC 命令触发。

---

**TUI 接入**：

```
runSmart()
    │
    ├── NewControlClient()            ← IPC 客户端
    ├── IsServiceRunning()            ← ping daemon
    │       若未运行 → startDaemon() fork --service 子进程
    │       waitForService(5s)        ← 100ms 间隔轮询
    └── runTUI(client)               ← 进入终端界面
```

---

**TUI 触发服务端启动**（用户在 TUI 中点击"启动服务端"）：

```
TUI → ControlClient.StartServer()
    │
    └── IPC → ControlServer.handleStartServer()
            └── VPNService.StartServer()
                    │
                    ├── getOrInitCertManager(isServer=true)
                    │       ├── 若 ca.pem/server.pem/server-key.pem 存在 → LoadServerCertificateManager()
                    │       └── 否则自动生成：
                    │               generateCACertificate()    RSA 4096，10 年，IsCA=true
                    │               generateCertificatePair()  RSA 4096，1 年，CN=vpn-server，SAN=[localhost,vpn-server]
                    │               保存 ca.pem(0644) / server.pem(0644) / server-key.pem(0600) / ca-key.pem(0400)
                    │
                    ├── NewVPNServer(addr, certMgr, config)
                    │       └── tls.Listen("tcp", addr, ServerTLSConfig())
                    │               ServerTLSConfig: MinVersion=MaxVersion=TLS1.3, RequireAndVerifyClientCert
                    │
                    ├── server.InitializeTUN()
                    │       ├── checkRootPrivileges()
                    │       ├── createTUNDevice("tun", config.Network)
                    │       │       /dev/net/tun + ioctl(TUNSETIFF, IFF_TUN|IFF_NO_PI)
                    │       ├── serverIP = base(.1)
                    │       ├── configureTUNDevice(tun.Name(), serverIP+"/24", MTU)
                    │       └── enableIPForwarding()   /proc/sys/net/ipv4/ip_forward = 1
                    │
                    ├── setupServerNAT(vpnCIDR, outIface)  [若 EnableNAT=true]
                    │       iptables -t nat -A POSTROUTING -s <vpnCIDR> -o <outIface> -j MASQUERADE
                    │       iptables -A FORWARD -i <tun> -o <outIface> -j ACCEPT
                    │       iptables -A FORWARD -i <outIface> -o <tun> -m state --state RELATED,ESTABLISHED -j ACCEPT
                    │       记录 natRules 供退出清理
                    │
                    ├── startCertAPIServer(certMgr)
                    │       └── HTTP ListenAndServe :8081
                    │               /api/cert/request  ← bootstrap 信任入口
                    │               /api/health        ← 探活
                    │
                    └── go server.Start(ctx)
                            ├── go handleTUNRead(ctx)      server TUN → 按目的IP转发至客户端
                            ├── go cleanupSessions(ctx)    定时清理超时会话
                            └── for { Accept() → go handleConnection(ctx, conn) }
```

**服务端就绪状态**：TLS listener 在 `:8080` 监听，TUN 已配置（如 `tun0`，IP `10.8.0.1/24`），Cert API 在 `:8081` 监听，NAT 已启用（若配置）。

---

### 4.2 阶段二：客户端 Bootstrap（证书申请）

客户端首次接入前，必须完成证书申请——这是进入 VPN 数据通道的前提。

```
[管理员] VPNService.GenerateToken(clientName)
    │
    ├── NewTokenManager() 或复用 apiServer.GetTokenManager()
    ├── rand.Read(32 bytes) → Token.Key（AES-256 key）
    ├── TokenID = "<clientName>-<timestamp>"
    └── 写入 tokenDir/<id>.json（0600 权限）
            { "id": "alice-20240101-120000",
              "key_hex": "a3f2...",  ← 32字节随机key的十六进制
              "expires_at": "...",
              "used": false }

[管理员将 TokenID + TokenKey 通过带外方式发送给客户端用户]
```

```
[客户端] VPNService.GenerateCSR(clientName)
    │
    ├── rsa.GenerateKey(rand.Reader, 4096)
    ├── x509.CreateCertificateRequest(...)    包含 CN=<clientName>
    ├── 写 <clientName>-key.pem（0600）       私钥不离开本机
    └── 写 <clientName>.csr（0644）

[客户端] VPNService.RequestCert(serverAddr, tokenID, tokenKey, csrFile)
    │
    ├── hex.DecodeString(tokenKey) → key[32]byte（严格校验长度）
    ├── os.ReadFile(csrFile)       → csrPEM
    ├── EncryptWithToken(csrPEM, key)
    │       aes.NewCipher(key) → GCM → rand nonce(12B) → gcm.Seal
    │       返回 ciphertext, nonce
    │
    ├── POST http://<serverAddr>:8081/api/cert/request
    │       Body: { token_id, encrypted_csr(base64), nonce(base64) }
    │
    │   [服务端 CertAPIServer.handleCertRequest()]
    │       ValidateAndUseToken(tokenID, clientIP)
    │           → token.Used = true → saveTokenToFile()（立即持久化）
    │       DecryptWithToken(encryptedCSR, nonce, token.Key) → csrPEM
    │       x509.ParseCertificateRequest(csrPEM)
    │       signCertificate(csr)
    │           x509.CreateCertificate(..., caCert, csr.PublicKey, caKey)
    │       EncryptWithToken(certPEM, token.Key)    → encCert, certNonce
    │       EncryptWithToken(caCertPEM, token.Key)  → encCA, caNonce
    │       Response: { success:true, encrypted_cert, encrypted_ca, nonce, ca_nonce }
    │
    ├── DecryptWithToken(encCert, nonce, key)   → certPEM
    ├── DecryptWithToken(encCA, caNonce, key)   → caPEM
    │
    └── 保存到 certDir/（0700 目录）：
            ca.pem         (0644)   CA 证书
            client.pem     (0644)   客户端证书
            client-key.pem (0600)   私钥（从 CSR 同目录复制）
```

**Bootstrap 完成**：客户端持有 `ca.pem`/`client.pem`/`client-key.pem`，具备进入 mTLS 通道的完整凭证。Token 已被标记为 `used=true`，无法再次使用。

---

### 4.3 阶段三：VPN 连接建立

```
[客户端] VPNService.ConnectClient()
    │
    ├── LoadCertificateManagerForClient(certDir)
    │       加载 ca.pem / client.pem / client-key.pem
    │       构建 ClientTLSConfig():
    │           Certificates: [clientCert]
    │           RootCAs:       caPool
    │           ServerName:    "vpn-server"      ← 必须匹配服务端 SAN
    │           MinVersion = MaxVersion = TLS1.3
    │
    ├── NewVPNClient(certMgr, config)
    ├── client.InitializeTUN()
    │       createTUNDevice("tun", "10.8.0.0/24")   ← IP 未配置，等服务端分配
    │
    └── go client.Run(ctx)
```

```
VPNClient.Connect(ctx)
    │
    ├── net.DialTimeout("tcp", serverAddr+":8080", 30s)
    ├── tls.Client(netConn, tlsConfig)
    ├── conn.Handshake()
    │       [TLS 1.3 握手]
    │       客户端发送：client cert + client hello
    │       服务端验证：PeerCertificates 非空 + CA 签发 + 未过期
    │           → handleConnection() 中 tls.Conn.(*tls.Conn) 断言 + Handshake()
    │
    ├── 验证 conn.ConnectionState().Version == tls.VersionTLS13
    │
    ├── 读第一条消息（13字节头）
    │       header[0]   = MessageTypeIPAssignment
    │       header[1:5] = length (big-endian)
    │       payload     = assignedIP (如 10.8.0.2)
    │       c.assignedIP = net.IP(payload)
    │
    ├── 读第二条消息
    │       header[0] = MessageTypeControl
    │       payload   = JSON(ClientConfig)
    │           { assigned_ip, server_ip, dns, routes,
    │             mtu, route_mode, exclude_routes,
    │             redirect_gateway, redirect_dns }
    │       合并进 c.config
    │
    ├── ConfigureTUN(assignedIP+"/24")
    │       ip addr add 10.8.0.2/24 dev tun0
    │       ip link set dev tun0 mtu <MTU> up
    │
    └── setupRoutes(routeMode, routes, serverAddr)
            split 模式: 逐条 ip route add <route> dev tun0
            full  模式: 备份默认路由 → ip route add 0.0.0.0/0 dev tun0
                        ExcludeRoutes 走原网关
            [可选] SaveDNS() → SetDNSForInterface(dns)
```

**连接建立完成状态**：
- 客户端 TUN（如 `tun0`）已配置 IP `10.8.0.2/24`
- 路由已安装，目标网段流量进入 TUN
- DNS 已接管（若 `RedirectDNS=true`）

---

### 4.4 阶段四：数据包穿透

以"客户端 ping `10.8.0.1`（服务端 VPN IP）"为例，追踪一个 ICMP 包的完整路径。

#### 4.4.1 客户端出站（TUN → TLS）

```
① 内核路由决策
   ping 发出 ICMP → 目的地 10.8.0.1 → 路由表匹配 10.8.0.0/24 dev tun0 → 包写入 tun0

② handleTUNRead goroutine
   n, _ = tun.ReadPacket(buf)        ← 从 tun0 读取原始 IP 包（阻塞，无 PI 头）
   
③ 封帧
   msg := Message{
       Type:    MessageTypeData,
       Length:  uint32(n),
       Sequence: atomic.AddUint32(&c.sendSeq, 1),
   }
   frame, _ = msg.Serialize()        ← [Type(1B)][Length(4B)][Payload(n B)]
   
④ TLS 发送
   c.conn.Write(frame)               ← TLS 1.3 AEAD 加密后发出
```

#### 4.4.2 服务端接收（TLS → TUN）

```
⑤ handleSessionData goroutine（对应客户端的会话）
   header = make([]byte, 13)
   io.ReadFull(conn, header)         ← 读固定头部
   msgType = MessageType(header[0])
   length  = BigEndian.Uint32(header[1:5])
   seq     = BigEndian.Uint32(header[5:9])
   
   payload = make([]byte, length)
   io.ReadFull(conn, payload)        ← 读 payload（原始 IP 包）
   
⑥ 写入服务端 TUN
   s.tunDevice.WritePacket(payload)  ← 注入 server tun0
   
⑦ 内核处理
   IP 包目的地 10.8.0.1 = server tun0 本机地址 → 内核直接处理 ICMP，生成回包
```

#### 4.4.3 服务端回程（TUN → TLS）

```
⑧ handleTUNRead goroutine（服务端）
   n, _ = s.tunDevice.ReadPacket(buf)      ← 读到 ICMP reply，目的地 10.8.0.2
   destIP = buf[16:20]                      ← IPv4 目的地址字段偏移量
   
⑨ 查找目标会话
   session = s.ipToSession[destIP.String()] ← O(1) map 查找
   
⑩ 封帧并发送
   sendDataResponse(session, buf[:n])
   session.TLSConn.Write(frame)
```

#### 4.4.4 客户端入站（TLS → TUN）

```
⑪ dataLoop goroutine
   io.ReadFull(c.conn, header)        ← 读帧头
   io.ReadFull(c.conn, payload)       ← 读 payload（ICMP reply）
   c.tunDevice.WritePacket(payload)   ← 写入 client tun0
   
⑫ 内核交付
   tun0 → 内核网络栈 → ping 进程接收 ICMP reply
```

#### 4.4.5 数据包路径总览

```
[客户端进程]  →  [client tun0]  →  [TLS 1.3]  →  [server tun0]  →  [内核/转发]
    ping            ReadPacket        Write            WritePacket      处理/转发
    recv            WritePacket       Read             ReadPacket       回包
[客户端进程]  ←  [client tun0]  ←  [TLS 1.3]  ←  [server tun0]  ←  [内核/转发]
```

所有传输均在 TLS 1.3 AEAD 加密保护下进行，物理链路上只有密文。

---

### 4.5 阶段五：连接维护

#### 4.5.1 心跳保活

客户端连接成功后，`startHeartbeat(ctx)` goroutine 定期发送心跳消息：

```go
ticker := time.NewTicker(heartbeatInterval)  // 默认 30s
for {
    select {
    case <-ctx.Done():
        return
    case <-ticker.C:
        msg := Message{Type: MessageTypeHeartbeat}
        frame, _ := msg.Serialize()
        c.conn.Write(frame)
        atomic.StoreInt64(&c.lastHeartbeat, time.Now().UnixNano())
    }
}
```

心跳的作用：
- 防止 NAT 设备因空闲超时关闭 UDP/TCP 映射
- 使服务端能检测到客户端已下线（`session.LastActivity` 超时）

#### 4.5.2 服务端会话超时清理

`cleanupSessions(ctx)` 定期扫描所有会话，清理超过 `SessionTimeout` 没有活动的会话：

```go
ticker := time.NewTicker(cleanupInterval)
for {
    select {
    case <-ctx.Done():
        return
    case <-ticker.C:
        now := time.Now()
        // 收集超时会话 ID（锁内）
        // 调用 removeSession()（锁外）：回收 IP + 关闭 TLS 连接
    }
}
```

每次收到数据包（无论是数据还是心跳），都会更新 `session.LastActivity`，从而刷新超时计时。

#### 4.5.3 断线重连

`VPNClient.Run(ctx)` 实现带退避的重连状态机：

```go
for atomic.LoadInt32(&c.reconnect) == 1 {
    err := c.Connect(ctx)
    if err != nil {
        c.retryCount++
        if c.retryCount > MaxRetries {
            log.Printf("达到最大重试次数，停止重连")
            break
        }
        backoff := time.Duration(c.retryCount) * RetryInterval  // 线性退避
        select {
        case <-ctx.Done():
            return
        case <-time.After(backoff):
        }
        continue
    }
    // 连接成功：启动 goroutine，进入转发循环
    c.retryCount = 0
    ...
    // 转发循环结束（连接断开）→ 清理后进入下一轮重连
    c.cleanupSession()
}
```

重连时会重新执行完整的连接建立流程（阶段三），包括重新配置 TUN IP 和路由（因为分配的 IP 可能变化）。

---

### 4.6 关键函数调用链索引

以下为各阶段核心调用链的快速索引，可作为源码阅读的入口：

| 阶段 | 入口函数 | 关键调用链 |
|------|---------|-----------|
| 服务端启动 | `VPNService.StartServer()` | `getOrInitCertManager` → `NewVPNServer` → `InitializeTUN` → `setupServerNAT` → `startCertAPIServer` → `server.Start` |
| 证书 bootstrap | `VPNService.GenerateCSR` + `RequestCert` | `rsa.GenerateKey` → `CreateCertificateRequest` → `EncryptWithToken` → `POST /api/cert/request` → `DecryptWithToken` → 落盘 |
| 证书 API 处理 | `CertAPIServer.handleCertRequest` | `ValidateAndUseToken` → `DecryptWithToken` → `signCertificate` → `EncryptWithToken` × 2 → JSON 返回 |
| 客户端连接 | `VPNService.ConnectClient()` | `LoadCertificateManagerForClient` → `NewVPNClient` → `InitializeTUN` → `client.Run` |
| TLS 握手 | `VPNClient.Connect` | `net.Dial` → `tls.Client` → `Handshake` → 读 IPAssignment → 读 Control → `ConfigureTUN` → `setupRoutes` |
| 出站转发 | `handleTUNRead`（客户端） | `tun.ReadPacket` → `Message.Serialize` → `conn.Write` |
| 入站转发 | `dataLoop`（客户端） | `io.ReadFull(header)` → `io.ReadFull(payload)` → `tun.WritePacket` |
| 服务端转发 | `handleTUNRead`（服务端） | `tun.ReadPacket` → `destIP=pkt[16:20]` → `ipToSession[destIP]` → `sendDataResponse` |
| 会话管理 | `handleConnection` | `tls.Handshake` → `PeerCerts检查` → `AllocateIP` → 发 IPAssignment → 发 Control → `handleSessionData` |

---

### 4.7 阶段总结

| 阶段 | 涉及模块 | 核心保障 |
|------|---------|---------|
| 服务端启动 | `main`、`vpn_service`、`cert_manager`、`vpn_server`、`tun_device`、`iptables_nat` | 自动生成 PKI；TUN + NAT 原子配置 |
| 客户端 Bootstrap | `token_manager`、`token_crypto`、`cert_api_server`、`vpn_service` | Token 单次使用防重放；私钥不出本机；AES-GCM 端到端加密 |
| 连接建立 | `cert_manager`、`vpn_client`、`tun_device`、`route_manager` | 强制 TLS 1.3 + mTLS；`ServerName` 与 SAN 匹配校验 |
| 数据穿透 | `vpn_client`、`vpn_server`、`protocol_message`、`tun_device` | 5 字节帧头解决流式分包；所有数据 TLS 1.3 加密传输 |
| 连接维护 | `vpn_client`（心跳/重连）、`vpn_server`（超时清理） | 心跳防 NAT 超时；线性退避重连；IP 池自动回收复用 |

---

## 第五章 证书、配置与 Token 安全链路

本章对证书体系、系统配置管理和 Token 安全链路进行专项深入分析。前四章已将这些模块作为流程节点描述，本章从"安全性设计"和"实现细节"角度做完整展开。

---

### 5.1 证书体系（`cert_manager.go`）

#### 5.1.1 PKI 拓扑

TLS-VPN 采用单级自建 CA，拓扑如下：

```
自建 CA（RSA 4096，10 年）
    ├── 服务端证书（RSA 4096，1 年，CN=vpn-server，SAN=[localhost, vpn-server]）
    └── 客户端证书 × N（RSA 4096，1 年，CN=<clientName>，每个客户端独立签发）
```

CA 私钥（`ca-key.pem`，0400 权限）仅在服务端磁盘上存储，客户端永远不持有 CA 私钥，符合标准 PKI 分离原则。

#### 5.1.2 CA 生成：`generateCACertificate()`

```go
privateKey, _ := rsa.GenerateKey(rand.Reader, 4096)

caTemplate := x509.Certificate{
    SerialNumber:          big.NewInt(1),
    Subject:               pkix.Name{CommonName: "TLS-VPN-CA"},
    NotBefore:             time.Now(),
    NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 年
    IsCA:                  true,
    KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
    ExtKeyUsage:           []x509.ExtKeyUsage{
                               x509.ExtKeyUsageServerAuth,
                               x509.ExtKeyUsageClientAuth,
                           },
    BasicConstraintsValid: true,
}

// 自签名：Issuer == Subject，用自身私钥签名
caCertDER, _ := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &privateKey.PublicKey, privateKey)
```

> 注意：EKU 同时包含 `ServerAuth` + `ClientAuth`，CA 可签发两类证书；实际应用中可按需拆分为不同用途的 Sub-CA。

#### 5.1.3 终端实体证书生成：`generateCertificatePair()`

服务端证书与客户端证书共用同一函数，通过 `isServer` 参数区分：

```go
func generateCertificatePair(isServer bool, caCert *x509.Certificate, caKey *rsa.PrivateKey) (tls.Certificate, error) {
    privateKey, _ := rsa.GenerateKey(rand.Reader, 4096)

    template := x509.Certificate{
        SerialNumber: generateSerialNumber(),          // crypto/rand 随机大整数
        NotBefore:    time.Now(),
        NotAfter:     time.Now().Add(365 * 24 * time.Hour), // 1 年
    }

    if isServer {
        template.Subject.CommonName = "vpn-server"
        template.DNSNames          = []string{"localhost", "vpn-server"} // SAN
        template.ExtKeyUsage       = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
    } else {
        template.Subject.CommonName = "vpn-client"
        template.ExtKeyUsage        = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
    }

    // 由 CA 签发（Issuer = CA Subject）
    certDER, _ := x509.CreateCertificate(rand.Reader, &template, caCert, &privateKey.PublicKey, caKey)
    ...
}
```

**服务端证书的 SAN 与客户端 `ServerName` 的耦合**：客户端 TLS 配置中 `ServerName: "vpn-server"`，必须能在服务端证书的 `DNSNames` 或 `CommonName` 中匹配，否则握手失败。这是系统可用性的关键配置耦合点：若需要通过 IP 访问服务端，需在 `IPAddresses` 中添加对应 IP。

#### 5.1.4 客户端证书：CSR 签发流程

服务端不在启动时生成通用客户端证书，而是按需通过 CSR 机制签发，每个客户端持有独立证书：

```go
// CertAPIServer.signCertificate(csr *x509.CertificateRequest)
func (api *CertAPIServer) signCertificate(csr *x509.CertificateRequest) ([]byte, error) {
    template := x509.Certificate{
        SerialNumber: generateSerialNumber(),
        Subject:      csr.Subject,           // 保留客户端 CSR 中的 CN/O 等字段
        NotBefore:    time.Now(),
        NotAfter:     time.Now().Add(365 * 24 * time.Hour),
        KeyUsage:     x509.KeyUsageDigitalSignature,
        ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
        // 使用 CSR 中的公钥
    }
    // 由 CA 签发
    certDER, err := x509.CreateCertificate(rand.Reader, &template, api.caCert, csr.PublicKey, api.caKey)
    ...
}
```

每个客户端证书的 `Subject.CommonName` 来自 CSR（由客户端在 `GenerateCSR(clientName)` 时写入），服务端可通过 `PeerCertificates[0].Subject.CommonName` 识别客户端身份，为后续权限控制扩展提供基础。

#### 5.1.5 证书加载：服务端模式与客户端模式

**服务端**：`NewCertificateManager(certDir)` 实现"存在则加载，不存在则生成"：

```go
func NewCertificateManager(certDir string) (*CertificateManager, error) {
    caPemPath     := certDir + "/ca.pem"
    serverPemPath := certDir + "/server.pem"
    serverKeyPath := certDir + "/server-key.pem"

    if fileExists(caPemPath) && fileExists(serverPemPath) && fileExists(serverKeyPath) {
        return LoadServerCertificateManager(certDir)
    }
    // 否则生成 CA + server cert 并保存
    return generateAndSave(certDir)
}
```

文件权限策略：

| 文件 | 权限 | 说明 |
|------|------|------|
| `ca.pem` | 0644 | CA 证书（公开分发给客户端） |
| `ca-key.pem` | 0400 | CA 私钥（仅 root 可读） |
| `server.pem` | 0644 | 服务端证书 |
| `server-key.pem` | 0600 | 服务端私钥 |
| `client.pem` | 0644 | 客户端证书 |
| `client-key.pem` | 0600 | 客户端私钥 |

**客户端**：`LoadCertificateManagerForClient(certDir)` 要求 `ca.pem`/`client.pem`/`client-key.pem` 三个文件全部存在，缺少任意一个则返回错误，强制先完成 bootstrap：

```go
func LoadCertificateManagerForClient(certDir string) (*CertificateManager, error) {
    for _, f := range []string{"ca.pem", "client.pem", "client-key.pem"} {
        if !fileExists(certDir + "/" + f) {
            return nil, fmt.Errorf("缺少证书文件 %s，请先申请证书", f)
        }
    }
    ...
}
```

#### 5.1.6 TLS 配置约束

```go
// 服务端
&tls.Config{
    Certificates: []tls.Certificate{serverCert},
    ClientAuth:   tls.RequireAndVerifyClientCert, // 强制 mTLS
    ClientCAs:    caPool,
    MinVersion:   tls.VersionTLS13,
    MaxVersion:   tls.VersionTLS13,               // 锁定 TLS 1.3，禁止降级
}

// 客户端
&tls.Config{
    Certificates: []tls.Certificate{clientCert},
    RootCAs:      caPool,
    ServerName:   "vpn-server",                   // 必须匹配服务端 SAN
    MinVersion:   tls.VersionTLS13,
    MaxVersion:   tls.VersionTLS13,
}
```

`MinVersion = MaxVersion = tls.VersionTLS13` 的效果：任何 TLS 1.2 及以下的连接尝试都会在握手阶段被拒绝，完全消除降级攻击面（BEAST、POODLE、DROWN 等历史漏洞均依赖旧版本）。

#### 5.1.7 证书有效期管理

当前实现未内置证书轮换机制：CA 有效期 10 年，服务端和客户端证书均为 1 年。实际部署中需注意：
- 1 年后客户端证书过期，握手失败（`x509: certificate has expired`）
- 解决方案：重新执行 bootstrap（重新 GenerateCSR + RequestCert），生成新的客户端证书

---

### 5.2 系统配置管理（`config.go`）

#### 5.2.1 配置结构体：`VPNConfig`

`VPNConfig` 是整个系统的单一配置来源，覆盖服务端、客户端、网络与安全所有参数：

```go
type VPNConfig struct {
    // 运行模式
    Mode          string `json:"mode"`           // "server" | "client"

    // 网络参数
    ServerAddress string `json:"server_address"` // 服务端地址（客户端连接目标）
    ServerPort    int    `json:"server_port"`     // VPN 数据通道端口（默认 8080）
    CertAPIPort   int    `json:"cert_api_port"`   // 证书 API 端口（默认 8081）
    Network       string `json:"network"`         // VPN 网段 CIDR（默认 10.8.0.0/24）
    MTU           int    `json:"mtu"`             // TUN MTU（默认 1420）

    // 路由与 DNS
    RouteMode     string   `json:"route_mode"`     // "full" | "split"
    Routes        []string `json:"routes"`          // split 模式下走 VPN 的网段
    ExcludeRoutes []string `json:"exclude_routes"`  // full 模式下排除的网段
    DNS           []string `json:"dns"`             // VPN 内 DNS 服务器
    RedirectDNS   bool     `json:"redirect_dns"`    // 是否接管 DNS

    // 安全与认证
    EnableNAT      bool `json:"enable_nat"`       // 是否在服务端启用 NAT 转发
    MaxConnections int  `json:"max_connections"`  // 服务端最大并发连接数

    // 会话管理
    SessionTimeout  int `json:"session_timeout"`  // 会话超时秒数（默认 300）
    HeartbeatInterval int `json:"heartbeat_interval"` // 心跳间隔秒数（默认 30）
    MaxRetries      int `json:"max_retries"`      // 客户端最大重连次数
}
```

#### 5.2.2 默认值：`DefaultConfig`

```go
var DefaultConfig = VPNConfig{
    ServerPort:        8080,
    CertAPIPort:       8081,
    Network:           "10.8.0.0/24",
    MTU:               1420,
    RouteMode:         "split",
    SessionTimeout:    300,
    HeartbeatInterval: 30,
    MaxConnections:    100,
    MaxRetries:        10,
}
```

MTU 设置为 1420 而非标准以太网的 1500，预留了 TLS 记录层头部和 IP/TCP 封装开销，避免分片。

#### 5.2.3 配置加载与写回

**加载**（daemon 启动时）：

```go
func LoadConfigFromFile(path string) (VPNConfig, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return VPNConfig{}, err  // 文件不存在时使用 DefaultConfig
    }
    var cfg VPNConfig
    err = json.Unmarshal(data, &cfg)
    return cfg, err
}
```

**写回**（TUI 修改配置后）：

```go
func SaveConfigToFile(cfg VPNConfig, path string) error {
    data, err := json.MarshalIndent(cfg, "", "  ")
    if err != nil {
        return err
    }
    return os.WriteFile(path, data, 0600)  // 配置文件含服务端地址等信息，权限收紧
}
```

配置文件为 JSON 格式，`MarshalIndent` 保持可读性，便于手动编辑。

#### 5.2.4 配置的"单一事实来源"模式

daemon 启动后，`VPNService.config` 字段是运行态的唯一配置引用：

```
config.json（磁盘）
    └─ LoadConfigFromFile() ─→ VPNService.config（内存）
                                    ├─ VPNServer（读取 Network/MTU/MaxConnections 等）
                                    ├─ VPNClient（读取 ServerAddress/Port/RouteMode 等）
                                    └─ CertAPIServer（读取 CertAPIPort）
```

TUI 通过 IPC `UpdateConfig` 命令修改配置时，ControlServer 会同时更新 `VPNService.config` 并写回 `config.json`，保持磁盘与内存的一致性。已运行的 VPN 连接不会因配置变更而自动重启，需手动断开重连使新配置生效。

#### 5.2.5 关键参数校验

加载配置时对以下字段进行校验：

| 字段 | 校验逻辑 |
|------|---------|
| `ServerPort` / `CertAPIPort` | 范围 1-65535，两者不能相同 |
| `Network` | 合法 CIDR（`net.ParseCIDR`），必须为 IPv4 |
| `MTU` | 范围 576-65535（IPv4 最小 MTU 为 576） |
| `RouteMode` | 枚举值 `"full"` 或 `"split"` |
| `SessionTimeout` | 大于 0 |
| `MaxConnections` | 大于 0 |

---

### 5.3 Token 安全链路（`token_manager.go` / `token_file.go`）

#### 5.3.1 Token 的完整生命周期

```
生成                    分发（带外）           使用                     过期/清理
  │                         │                    │                         │
GenerateToken()         管理员手动               RequestCert()         CleanupExpired()
  │                     发送给客户端               │                         │
  ├─ rand.Read(32B)     （邮件/即时通讯等）       ValidateAndUseToken()  遍历 tokenDir
  ├─ ID=name+timestamp                             │                     删除 used 或
  ├─ ExpiresAt=now+TTL                             ├─ 检查 exists          expired 文件
  └─ 写 tokenDir/<id>.json                        ├─ 检查 !used
       0600 权限                                   ├─ 检查 !expired
                                                   ├─ token.Used=true
                                                   ├─ token.UsedAt=now
                                                   ├─ token.UsedBy=clientIP
                                                   └─ saveTokenToFile()（持久化）
```

#### 5.3.2 Token 文件格式

落盘的 JSON 文件（存储于 `tokenDir/`，如 `~/.tls-vpn/tokens/<id>.json`）：

```json
{
  "id": "alice-20240101-120000",
  "client_name": "alice",
  "key_hex": "a3f2b1c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2",
  "created_at": "2024-01-01T12:00:00Z",
  "expires_at": "2024-01-08T12:00:00Z",
  "used": false,
  "used_at": null,
  "used_by": ""
}
```

> `key_hex` 是 32 字节随机值的十六进制编码（64 个字符），即 AES-256 key。`Token.Key []byte` 字段标注了 `json:"-"` 不直接序列化，由 `saveTokenToFile` 显式编码为 `key_hex`，加载时解码回 `[]byte`。

#### 5.3.3 Token Manager 的关键实现

**并发安全**：`TokenManager` 内部使用 `sync.RWMutex`，`ValidateAndUseToken` 全程持写锁，防止同一 Token 被并发请求双重使用：

```go
func (tm *TokenManager) ValidateAndUseToken(id, clientIP string) (*Token, error) {
    tm.mu.Lock()
    defer tm.mu.Unlock()

    token, exists := tm.tokens[id]
    if !exists {
        return nil, fmt.Errorf("Token不存在: %s", id)
    }
    if token.Used {
        return nil, fmt.Errorf("Token已被使用 (by %s at %s)", token.UsedBy, token.UsedAt)
    }
    if time.Now().After(token.ExpiresAt) {
        return nil, fmt.Errorf("Token已过期")
    }

    token.Used   = true
    token.UsedAt = time.Now()
    token.UsedBy = clientIP
    tm.saveTokenToFile(token)  // 持久化，防止重启后重用
    return token, nil
}
```

**启动加载**：`NewTokenManagerWithLoad(dir)` 在 `CertAPIServer` 初始化时调用，从 `tokenDir` 加载所有 `.json` 文件，确保服务重启后历史 Token 状态（已使用/已过期）不丢失：

```go
func NewTokenManagerWithLoad(dir string) *TokenManager {
    tm := &TokenManager{tokens: make(map[string]*Token), dir: dir}
    entries, _ := os.ReadDir(dir)
    for _, e := range entries {
        if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
            token, err := loadTokenFromFile(dir + "/" + e.Name())
            if err == nil {
                tm.tokens[token.ID] = token
            }
        }
    }
    return tm
}
```

这保证了**跨重启的单次使用语义**：即便服务端重启，已使用过的 Token 仍不能再次使用。

#### 5.3.4 Token 有效期策略

`GenerateToken(clientName, ttl)` 接受 TTL 参数，默认有效期通常为 7 天，适合"管理员提前生成、客户端在一周内完成注册"的工作流。

有效期设计的工程权衡：
- **过短**（如 1 小时）：客户端需要快速操作，运维压力大
- **过长**（如 1 年）：Token 泄露后攻击窗口大
- **建议**：7-30 天，并在客户端成功申请证书后立即废弃（已通过 `used=true` 机制实现）

#### 5.3.5 Token 与证书的安全边界

```
Token 生命周期（短暂）          证书生命周期（长期）
─────────────────────          ──────────────────────
有效期：7 天                   有效期：1 年
保密需求：高（含 AES-256 key） 保密需求：中（私钥 0600；证书公开）
撤销方式：过期/删除文件         撤销方式：需重新 bootstrap
用途：一次性 bootstrap         用途：每次 VPN 连接的 mTLS 鉴权
作用范围：仅证书申请阶段        作用范围：整个 VPN 数据通道
```

一旦客户端证书申请完成，Token 的安全性就不再影响 VPN 通道的安全性——即便 Token 文件泄露，攻击者也无法用其建立 VPN 连接（VPN 连接只接受证书认证）。

---

### 5.4 安全链路全景

将证书体系、配置管理和 Token 链路整合为一张全景视图：

```
[管理员操作]                        [客户端操作]
     │                                   │
GenerateToken()                    GenerateCSR()
  32B random key                     RSA 4096 私钥（本地保存）
  写 .json 0600                       .csr 文件
     │                                   │
     │ 带外传递 TokenID + TokenKey        │
     └────────────────────────────────>  │
                                         │ RequestCert()
                                         │   EncryptWithToken(CSR, key)
                                         │   POST http://server:8081
                                         │         ↓
                                   handleCertRequest()
                                     ValidateAndUseToken() → used=true
                                     DecryptWithToken(CSR)
                                     signCertificate(csr) ← CA 私钥签发
                                     EncryptWithToken(cert + ca, key)
                                         │
                                         │ DecryptWithToken(cert)
                                         │ 落盘 ca.pem / client.pem / client-key.pem
                                         │
                                   [Bootstrap 完成，Token 失效]
                                         │
                                    ConnectClient()
                                     LoadCertificateManagerForClient()
                                     tls.Dial + Handshake (TLS 1.3)
                                         ↓
                                   VPNServer 验证 mTLS
                                   AllocateIP → 推送配置
                                         ↓
                                   [VPN 隧道建立，Token 不再参与]
```

---

### 5.5 潜在安全改进点

**证书吊销**：当前没有实现 CRL（证书吊销列表）或 OCSP。若客户端私钥泄露，唯一的撤销方式是手动删除服务端 CA 签发给该客户端的证书——但由于服务端不维护"已签发证书列表"，实际上只能重新生成 CA（影响所有客户端）。改进方向：在 `CertAPIServer` 中维护已签发证书的 Serial Number 列表，并在 `ServerTLSConfig` 的 `VerifyPeerCertificate` 回调中进行吊销检查。

**Token 传输安全**：Token（含 AES key）目前通过"带外方式"分发（邮件、即时通讯等），若传输渠道不安全，Token 可能被中间人截获。由于 Token 有效期较短（7天）且单次使用，实际风险可控；但若需要更高安全保证，可考虑通过 HTTPS 或已认证的通道分发 Token。

**CA 密钥保护**：`ca-key.pem` 以 0400 权限存储在服务端磁盘，服务器被攻陷时将导致 CA 私钥泄露（可伪造任意客户端证书）。改进方向：使用 HSM 或软件 TPM 存储 CA 私钥，或将 CA 离线保存，仅在需要签发证书时临时加载。

**配置文件权限**：`config.json` 当前以 0600 权限保存，包含服务端地址等信息；若包含预共享密钥等敏感字段，需确保运行用户的权限最小化。

---

## 第六章 生命周期与退出机制

本章完整描述 TLS-VPN 后台服务（daemon）的生命周期：从进程启动、守护驻留，到两种退出路径的清理链路，以及各子系统资源回收的细节与工程设计要点。

---

### 6.1 Daemon 进程模型

TLS-VPN 采用**前台 TUI + 后台 Daemon 分离**的架构：

```
用户终端
  └── 前台进程（TUI）
        │  Unix Socket IPC
        └── 后台进程（Daemon，--service）
              ├── ControlServer（本地控制 API）
              └── VPNService（数据面，按需启动）
```

关键设计原则：**退出 TUI 不会停止后台服务**，服务可以持续运行；数据面（VPN Server/Client）在 daemon 启动时并不自动运行，需要通过 IPC 命令显式触发。

---

### 6.2 Daemon 启动：`runServiceDaemon()`

`runServiceDaemon()` 是后台服务的完整初始化序列：

```go
func runServiceDaemon() {
    // 1. 初始化日志
    logWriter, _ := NewRotatingFileWriter(DefaultLogPath, 10, 5)
    logger := InitServiceLogger(logWriter)
    log.SetOutput(logger)
    log.SetFlags(log.Ldate | log.Ltime)
    log.Printf("TLS VPN 服务启动 (PID: %d)", os.Getpid())

    // 2. 创建服务实例（加载配置）
    service := NewVPNService()

    // 3. 启动控制面 IPC
    controlServer := NewControlServer(service)
    if err := controlServer.Start(); err != nil {
        log.Fatalf("启动控制服务器失败: %v", err)
    }

    // 4. 阻塞等待退出信号
    sigChan := setupSignalHandler()
    <-sigChan
    log.Println("收到退出信号，正在停止服务...")

    // 5. 有序清理
    service.Cleanup()
    controlServer.Stop()
    log.Println("TLS VPN 服务已退出")
}
```

**数据面延迟启动**：daemon 启动后仅暴露 IPC 接口，VPN Server/Client 的真正启动由用户通过 TUI 或 `--status` 命令触发，这为运维/调试提供了更细粒度的控制。

---

### 6.3 Daemon 拉起：`startDaemon()`（跨平台自守护）

Smart 启动模式（默认）在检测到后台未运行时，通过 `startDaemon()` 将自身以 `--service` 参数重新启动为后台子进程：

**Unix/Linux（`daemon_unix.go`）**：

```go
cmd := exec.Command(executable, "--service")
cmd.SysProcAttr = &syscall.SysProcAttr{
    Setsid: true,  // 新会话 leader，脱离父终端
}
cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
cmd.Start()
go cmd.Wait()  // 防止僵尸进程
```

`Setsid: true` 使子进程成为新会话 leader，不再依附于启动它的终端；stdin/stdout/stderr 全部置空，日志完全由轮转文件系统处理。

**Windows（`daemon_windows.go`）**：

```go
cmd := exec.Command(executable, "--service")
cmd.SysProcAttr = &syscall.SysProcAttr{
    CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
    HideWindow:    true,
}
cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
cmd.Start()
go cmd.Wait()
```

两者均不依赖 systemd 或 Windows Service Manager，实现跨平台"自守护"能力（生产环境推荐注册为系统服务以获得自动重启等能力）。

---

### 6.4 信号处理：`setupSignalHandler()`（跨平台）

`setupSignalHandler()` 按平台分文件实现，返回缓冲为 1 的信号通道：

**Unix/Linux（`signal_unix.go`）**：

```go
func setupSignalHandler() chan os.Signal {
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
    return sigChan
}
```

- `SIGINT`：Ctrl+C，前台调试时常见
- `SIGTERM`：systemd/docker/k8s 标准停止信号，daemon 部署时最常见

**Windows（`signal_windows.go`）**：

```go
func setupSignalHandler() chan os.Signal {
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, os.Interrupt)
    return sigChan
}
```

缓冲为 1 保证信号不会因无接收者而丢失；同时意味着短时间内多次信号只保留一个（对优雅退出足够）。

**TUI 中的信号处理**与 daemon 不同——TUI 收到信号后只停止 UI（`app.Stop()`），不停止后台 daemon：

```go
func runTUI(client *ControlClient) {
    sigChan := setupSignalHandler()
    app := NewTUIApp(client)
    go func() { <-sigChan; app.Stop() }()
    app.Run()
}
```

---

### 6.5 退出路径

Daemon 的退出有两条独立但等价的路径，最终都调用同一个 `VPNService.Cleanup()`：

#### 6.5.1 路径 A：OS 信号退出

```
OS 发送 SIGINT/SIGTERM
    │
    └── runServiceDaemon() 中 <-sigChan 解除阻塞
            │
            ├── service.Cleanup()    ← 数据面清理（见 6.6）
            └── controlServer.Stop() ← 关闭 IPC socket
```

顺序语义：**先清理数据面（VPN 业务资源）→ 再关闭控制面（停止接受新 IPC 请求）**，避免退出期间并发接收新的 start/connect 命令。

#### 6.5.2 路径 B：IPC Shutdown（`./tls-vpn --stop`）

```
用户执行 ./tls-vpn --stop
    │
    └── ControlClient.Shutdown()  → IPC ActionShutdown
            │
            └── ControlServer.handleShutdown()
                    │
                    ├── 先返回响应：{ success:true, message:"服务正在关闭..." }
                    │   （确保 CLI 能收到结果，不误判失败）
                    │
                    └── go func() {          ← 异步执行，避免提前断开 socket
                            s.service.Cleanup()
                            s.Stop()         ← 关闭 IPC socket
                            os.Exit(0)       ← 确保进程退出
                        }()
```

`os.Exit(0)` 在 IPC 路径中是必要的——否则进程可能停留在某个阻塞点（如 `<-sigChan`）无法自动退出。

---

### 6.6 资源清理总闸门：`VPNService.Cleanup()`

```go
func (s *VPNService) Cleanup() {
    s.mu.Lock()
    defer s.mu.Unlock()

    if s.server != nil {
        s.server.Stop()    // 服务端数据面清理
        s.server = nil
    }
    if s.client != nil {
        s.client.Close()   // 客户端数据面清理
        s.client = nil
    }
    if s.apiServer != nil {
        s.apiServer.Stop() // 证书 API 服务清理
        s.apiServer = nil
    }
}
```

三个设计要点：

**互斥锁保护**：持 `s.mu.Lock()` 确保清理过程不会与 ControlServer 并发的 start/stop/connect 命令产生资源竞态。

**幂等化**：每个对象 Stop/Close 后置 `nil`，下次调用 Cleanup 时跳过，避免重复清理。

**子系统自治**：`VPNService` 不直接操作路由/DNS/iptables/TUN，每个子系统（server/client/apiServer）各自负责回收自己引入的系统副作用。

> 潜在改进：当前在锁内调用 `server.Stop()` / `client.Close()`，而这些操作可能包含阻塞的系统调用（iptables、ip route 等）。更稳妥的做法是在锁内取出引用并置 nil，在锁外执行 Stop/Close，减少控制面请求被阻塞的时间窗口。

---

### 6.7 服务端退出细节：`VPNServer.Stop()`

退出顺序：`取消协程 → 关闭 Listener → 踢出所有会话 → 清理 NAT → 关闭 TUN`

```go
func (s *VPNServer) Stop() {
    // 1. 取消内部 context → 通知所有协程退出
    s.cancel()

    // 2. 关闭 listener → 立即打断 Accept() 阻塞
    s.listener.Close()

    // 3. 收集 session ID（锁内），再逐一移除（锁外）
    s.sessionMutex.Lock()
    ids := make([]string, 0, len(s.sessions))
    for id := range s.sessions { ids = append(ids, id) }
    s.sessionMutex.Unlock()

    for _, id := range ids {
        s.removeSession(id)  // 回收 IP + 关闭 TLS 连接
    }

    // 4. 清理 NAT 规则（iptables -D）
    s.cleanupNATRules()

    // 5. 关闭 TUN 设备（使 handleTUNRead 阻塞读立即返回错误）
    deviceName := s.tunDevice.Name()
    s.tunDevice.Close()
    cleanupTUNDevice(deviceName)
}
```

**步骤 1（cancel）的效果**：`handleTUNRead`、`cleanupSessions`、以及监听 `<-ctx.Done()` 的 goroutine 均退出；`Start()` 主循环在 `Accept()` 返回错误后因 `ctx.Err() != nil` 而 break。

**步骤 2（listener.Close）的必要性**：`cancel()` 后 `Accept()` 不一定立即返回——显式关闭 listener 确保 Accept 立即报错，不需要等待 context 轮询。

**步骤 3（removeSession 两阶段）**：锁内只做 map 删除和 IP 回收，锁外才执行 `session.Close()`（TLSConn.Close），避免持锁期间做网络 IO 导致长时间阻塞或死锁。`VPNSession.Close()` 带幂等保护：

```go
func (s *VPNSession) Close() error {
    s.mutex.Lock()
    defer s.mutex.Unlock()
    if s.closed { return nil }  // 已关闭则跳过
    s.closed = true
    return s.TLSConn.Close()
}
```

**步骤 4（NAT 清理）**：在会话全部关闭后再删 iptables 规则，此时已无流量需要 NAT，清理更安全；失败仅记 warning，不阻断退出流程。

**步骤 5（TUN 关闭）放在最后**：关闭 TUN 句柄会使 `handleTUNRead` 的阻塞 `ReadPacket` 立即返回错误，加速转发协程退出（与 cancel 形成双保险）。

---

### 6.8 客户端退出细节：`VPNClient.Close()`

退出顺序：`停止重连/协程 → 回滚路由+DNS → 断开 TLS 连接 → 关闭 TUN`

```go
func (c *VPNClient) Close() {
    // 1. 停止重连循环
    atomic.StoreInt32(&c.reconnect, 0)

    // 2. 取消主 context → 停止心跳、TUN 读、数据接收协程
    c.cancelMutex.Lock()
    if c.cancel != nil { c.cancel() }
    c.cancelMutex.Unlock()

    // 3. 回滚系统副作用
    if c.routeManager != nil {
        c.routeManager.CleanupRoutes()   // ip route del（逐条）
        c.routeManager.RestoreDNS()      // 恢复 /etc/resolv.conf
    }

    // 4. 关闭 TLS 连接（使 dataLoop 中的阻塞读立即返回错误）
    c.closeConnection()

    // 5. 关闭 TUN（使 handleTUNRead 的阻塞读立即返回错误）
    if c.tunDevice != nil {
        deviceName := c.tunDevice.Name()
        c.tunDevice.Close()
        cleanupTUNDevice(deviceName)
    }
}
```

**步骤 1+2（停重连+cancel）**：`reconnect=0` 终止 `Run()` 的外层 `for` 循环；`cancel()` 向心跳、TUN 读、数据接收三个 goroutine 发送停止信号，它们均在 `select { case <-ctx.Done(): return }` 处退出。

**步骤 3（路由+DNS 回滚先于断连）**：路由回滚发生在断开 TLS 连接之前，保证在系统网络配置恢复期间 TLS 连接还存在，避免中间状态影响其他应用的连通性。`RestoreDNS()` 有安全阀——若备份文件不存在则跳过，不会破坏系统 DNS：

```go
func (rm *RouteManager) RestoreDNS() error {
    if _, err := os.Stat("/etc/resolv.conf.vpn-backup"); os.IsNotExist(err) {
        log.Println("没有找到DNS备份文件，跳过恢复")
        return nil
    }
    data, _ := os.ReadFile("/etc/resolv.conf.vpn-backup")
    os.WriteFile("/etc/resolv.conf", data, 0644)
    os.Remove("/etc/resolv.conf.vpn-backup") // 删除备份，防止下次误用
    return nil
}
```

**步骤 4+5（断连+关TUN 双保险）**：关闭 TLS 连接后 `dataLoop` 的 `io.ReadFull` 立即报错退出；关闭 TUN 后 `handleTUNRead` 的阻塞读立即报错退出——两者形成双保险，确保所有 goroutine 能快速退出而非挂起。

---

### 6.9 退出清理覆盖范围

#### 服务端（`VPNServer.Stop()`）

| 资源 | 清理动作 | 清理时机 |
|------|---------|---------|
| 后台 goroutine | `cancel()` 触发 `ctx.Done` | 步骤 1 |
| TLS listener | `listener.Close()` | 步骤 2 |
| 客户端 TLS 会话 | `VPNSession.Close()` × N | 步骤 3（锁外） |
| 虚拟 IP 租约 | `IPPool.ReleaseIP()` × N | 步骤 3（锁内） |
| iptables NAT 规则 | `iptables -D` × N | 步骤 4 |
| TUN 设备 | `tunDevice.Close()` + `ip link set down` | 步骤 5 |

#### 客户端（`VPNClient.Close()`）

| 资源 | 清理动作 | 清理时机 |
|------|---------|---------|
| 重连循环 | `atomic.StoreInt32(&reconnect, 0)` | 步骤 1 |
| 后台 goroutine | `cancel()` 触发 `ctx.Done` | 步骤 2 |
| 系统路由条目 | `ip route del` × N | 步骤 3 |
| DNS 配置 | 恢复 `/etc/resolv.conf` | 步骤 3 |
| TLS 连接 | `conn.Close()` | 步骤 4 |
| TUN 设备 | `tunDevice.Close()` + `ip link set down` | 步骤 5 |

---

### 6.10 工程设计总结

**统一收口**：无论是 OS 信号还是 IPC Shutdown，都经过同一个 `VPNService.Cleanup()`，保证资源回收路径唯一、行为一致。

**可逆性设计**：路由（`installedRoutes` 列表）和 DNS（`.vpn-backup` 备份文件）均采用"安装时记录、退出时回滚"模式，即使异常退出也能尽量恢复系统网络状态。

**双保险退出**：每个阻塞 goroutine 既监听 `ctx.Done()`（软信号），又依赖底层句柄关闭（硬中断），两者配合保证 goroutine 快速退出不挂起。

**幂等保护**：`VPNSession.Close()` 有 `closed` 标志位，`VPNService.Cleanup()` 置 nil 后跳过，防止重复清理导致 panic。

**退出顺序约束**：`数据面先停，控制面后停`；客户端 `路由回滚先于断连`；服务端 `会话关闭先于NAT清理，NAT清理先于TUN关闭`——每个顺序都有明确的工程理由。

---

## 附录：文档说明

- 技术正文覆盖模块：27 个核心模块（含 Part-1 至 Part-27 全部内容）
- 源码引用版本：commit `0b4aeb078ef20f99df212e765cab14c4b6a55145`
- 优化方式：移除 AI 对话过渡语、引导性问题及重复目录；统一代码块格式；章节结构保持不变
