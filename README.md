# TLS-VPN

[![Go Version](https://img.shields.io/badge/Go-1.24.0-00ADD8?style=flat&logo=go)](https://golang.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-blue.svg)](#系统要求)

基于 **TLS 1.3 + TUN（L3）隧道** 的跨平台自建 VPN 系统，使用 Go 开发。集成自建 PKI、Token 注册体系、交互式 TUI 管理界面与后台守护进程，无需依赖 OpenVPN 或 WireGuard 守护进程。

---

## 目录

- [项目特性](#项目特性)
- [安全模型](#安全模型)
- [系统要求](#系统要求)
- [快速开始](#快速开始)
- [编译与构建](#编译与构建)
- [运行模式与命令](#运行模式与命令)
- [典型部署流程](#典型部署流程)
- [配置文件说明](#配置文件说明)
- [证书与 Token 机制](#证书与-token-机制)
- [网络行为详解](#网络行为详解)
- [TUI 菜单总览](#tui-菜单总览)
- [项目结构](#项目结构)
- [日志与运行状态](#日志与运行状态)
- [故障排查](#故障排查)
- [安全建议](#安全建议)
- [开发参考](#开发参考)

---

## 项目特性

### 安全与认证

- **强制 TLS 1.3**：`MinVersion = MaxVersion = TLS 1.3`，杜绝协议降级攻击
- **双向证书认证（mTLS）**：服务端 `RequireAndVerifyClientCert`，无证书连接直接拒绝
- **自建 PKI**：自动生成 CA（RSA 4096，10 年）与服务端证书（RSA 4096，1 年）
- **Token 驱动的 Bootstrap**：客户端通过一次性 Token 申请证书；Token 单次使用，防重放攻击
- **私钥不出本机**：客户端在本地生成 RSA 4096 私钥与 CSR，仅 CSR 经网络传输
- **AES-256-GCM 端到端加密**：证书申请通道使用 Token Key 作为对称密钥加密 CSR 与证书

### 网络能力

- **L3 TUN 隧道**：基于用户态 TUN 设备实现三层 IP 转发
- **跨平台 TUN**：Linux 通过 `github.com/songgao/water` 库创建 TUN 设备（底层封装了 `/dev/net/tun`），Windows 通过 `golang.zx2c4.com/wireguard` 使用 Wintun 驱动；地址与路由均通过 `ip` 命令配置
- **路由模式**：`split`（分流，仅指定网段走 VPN）、`full`（全流量，重定向默认网关）
- **DNS 推送与接管**：服务端推送 DNS 配置，支持可选 DNS 劫持（`redirect_dns`）
- **Linux NAT**：服务端自动配置 iptables MASQUERADE + FORWARD 规则，可开关
- **心跳保活 + 断线自动重连**：客户端线性退避重连，服务端超时会话自动清理
- **IP 地址池管理**：服务端按 CIDR 分配虚拟 IP，断线后自动回收复用
- **多客户端转发**：服务端维护 `ipToSession` map，O(1) 按目的 IP 查找客户端会话

### 运维与可视化

- **交互式 TUI**：菜单化管理，支持快速向导一键部署
- **智能启动**：自动拉起后台 Daemon 并进入 TUI，无感操作
- **前后台分离**：退出 TUI 不停止后台服务，VPN 隧道持续工作
- **本地控制 API**：Unix Socket IPC，TUI 与 Daemon 之间的状态同步与命令下发
- **在线客户端管理**：查看连接列表、流量统计、踢出指定客户端
- **配置持久化**：支持保存/加载/重置，JSON 格式，手动可编辑
- **日志轮转**：自动轮转文件（默认 10 MB/文件，保留 5 个备份），TUI 实时拉取展示

---

## 安全模型

TLS-VPN 采用**两段式安全模型**，将证书 Bootstrap 与 VPN 数据通道完全隔离：

```
第一段：证书申请（HTTP 8081，Token 驱动，一次性）
┌─────────────────────────────────────────────────────────────────┐
│  客户端生成 CSR（私钥本地保存）                                  │
│  EncryptWithToken(CSR, AES-256-GCM)                             │
│  POST http://server:8081/api/cert/request                        │
│       ↓                                                          │
│  服务端验证 Token（存在/有效/未使用）→ 标记 used=true（防重放） │
│  CA 私钥签发客户端证书 → EncryptWithToken(cert + ca) 返回       │
│  客户端解密落盘 ca.pem / client.pem / client-key.pem            │
└─────────────────────────────────────────────────────────────────┘
             ↓ Bootstrap 完成，Token 失效

第二段：VPN 数据通道（TCP 8080，TLS 1.3 + mTLS，长连接）
┌─────────────────────────────────────────────────────────────────┐
│  tls.Dial → TLS 1.3 握手（双向证书验证）                        │
│  服务端验证 PeerCertificates（无证书即拒绝）                     │
│  下发虚拟 IP + 路由/DNS 配置                                     │
│  TUN ←→ TLS 1.3 AEAD 加密 ←→ TUN（全程密文传输）              │
└─────────────────────────────────────────────────────────────────┘
```

---

## 系统要求

### 通用

| 要求 | 说明 |
|------|------|
| Go 版本 | 1.24+ |
| 权限 | Linux：root 或 `CAP_NET_ADMIN`；Windows：管理员权限 |
| 网络 | 能创建 TUN 虚拟网卡 |

### Linux

- `iproute2`（`ip` 命令）
- `iptables`（启用 NAT 时需要）
- 可写 `/var/run`、`/var/log`

### Windows

- Windows 10 / 11（推荐）
- 管理员权限运行
- Wintun 驱动（通过 Go 依赖自动引入，无需手动安装）

---

## 快速开始

### 一、下载或编译

```bash
# 克隆仓库
git clone <repo-url>
cd tls-vpn/source

# 编译（Linux）
go mod download
go build -o ../build/tls-vpn .

# 编译（Windows PowerShell）
go mod download
go build -o ..\build\tls-vpn.exe .
```

### 二、启动程序

```bash
# Linux（需要 root）
sudo ./build/tls-vpn

# Windows（管理员 PowerShell）
.\build\tls-vpn.exe
```

程序启动后自动进入交互式 TUI 界面，可通过**快速向导**完成服务端部署或客户端接入。

---

## 编译与构建

> 源码位于 `source/` 目录，所有构建命令在该目录内执行。

### 本机构建

```bash
# Linux / macOS
cd source
go mod download
go build -o ../build/tls-vpn .

# Windows PowerShell
Set-Location .\source
go mod download
go build -o ..\build\tls-vpn.exe .
```

### 交叉编译

```bash
# Linux 编译 Windows 可执行文件
cd source
GOOS=windows GOARCH=amd64 go build -o ../build/tls-vpn.exe .

# Windows 编译 Linux 可执行文件（PowerShell）
Set-Location .\source
$env:GOOS="linux"; $env:GOARCH="amd64"
go build -o ..\build\tls-vpn .
```

---

## 运行模式与命令

```
用法：
  tls-vpn                  智能启动（自动拉起后台 + 进入 TUI）
  tls-vpn --service        仅启动后台服务（Daemon 模式）
  tls-vpn --status         查看服务状态与当前配置
  tls-vpn --stop           停止后台服务
  tls-vpn --help           显示帮助
```

### 智能启动（默认，推荐）

执行 `./build/tls-vpn` 时：

1. 检测后台 Daemon 是否已运行
2. 若未运行，自动 fork 一个 `--service` 子进程（Linux 使用 `Setsid` 脱离终端，Windows 使用 `CREATE_NEW_PROCESS_GROUP`）
3. 最多等待 5 秒直至控制 API 就绪
4. 启动 TUI，通过 IPC 控制后台服务

> 退出 TUI 不会停止后台服务，VPN 隧道持续工作。

### Daemon 模式（`--service`）

- 启动后台服务进程，不进入 TUI
- 暴露本地控制 API（Unix Socket）
- 数据面（VPN Server/Client）不自动启动，需通过 TUI 或 IPC 命令触发

### 状态与停止

```bash
# 查看状态（服务是否运行、端口、连接数、TUN、流量、当前配置）
./build/tls-vpn --status

# 优雅停止（通过 IPC 下发 shutdown，等待资源清理后退出）
./build/tls-vpn --stop
```

---

## 典型部署流程

### 服务端（机器 A）

```
1. 启动程序
   sudo ./build/tls-vpn

2. 进入 TUI → 快速向导 → 服务端快速部署
   - 设置监听端口（默认 8080）
   - 设置 VPN 网段（默认 10.8.0.0/24）
   - 选择路由模式（split / full）
   - 自动生成 CA + 服务端证书
   - 启动服务端

3. Token 管理 → 生成 Token
   - 填写客户端名称（如 alice）
   - 设置有效期（默认 7 天）
   - 记录生成的 TokenID 和 TokenKey（格式：ID:KEY）

4. 将 TokenID:TokenKey 通过安全渠道发送给客户端用户

5. 确保防火墙放行：
   - 8080/tcp（VPN 数据通道）
   - 8081/tcp（证书申请 API，可在申请完成后关闭）
```

### 客户端（机器 B）

```
1. 启动程序
   sudo ./build/tls-vpn  （Linux）
   .\build\tls-vpn.exe   （Windows 管理员）

2. 进入 TUI → 快速向导 → 客户端快速配置
   - 填写服务端地址和端口
   - 生成 CSR（客户端在本地生成 RSA 4096 私钥）
   - 输入 TokenID 和 TokenKey，申请证书
   - 证书申请成功后，自动连接 VPN

3. 连接成功后，TUI 显示分配的虚拟 IP（如 10.8.0.2）
```

---

## 配置文件说明

默认配置文件路径：`./config.json`（与可执行文件同目录）

程序启动时自动加载；TUI 修改配置后实时写回。

### 完整字段说明

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `server_address` | string | `""` | 客户端连接的服务端地址（服务端模式下无需设置） |
| `server_port` | int | `8080` | VPN 数据通道 TLS 监听端口 |
| `cert_api_port` | int | `8081` | 证书申请 HTTP API 端口 |
| `network` | string | `10.8.0.0/24` | VPN 虚拟网段（CIDR） |
| `server_ip` | string | `10.8.0.1/24` | 服务端 TUN 接口地址 |
| `client_ip_start` | int | `2` | 客户端地址池起始主机号 |
| `client_ip_end` | int | `254` | 客户端地址池结束主机号 |
| `mtu` | int | `1420` | TUN 接口 MTU（预留 TLS 封装开销） |
| `route_mode` | string | `split` | 路由模式：`split`（分流）/ `full`（全流量） |
| `push_routes` | []string | `[]` | split 模式下推送给客户端的路由网段 |
| `exclude_routes` | []string | `[]` | full 模式下排除（不走 VPN）的路由网段 |
| `dns_servers` | []string | `["8.8.8.8","8.8.4.4"]` | 推送给客户端的 DNS 服务器 |
| `redirect_gateway` | bool | `false` | 是否重定向客户端默认网关至 VPN |
| `redirect_dns` | bool | `false` | 是否接管客户端 DNS |
| `enable_nat` | bool | `true` | 服务端是否启用 iptables NAT 转发 |
| `nat_interface` | string | `""` | NAT 出口网卡，空字符串表示自动检测 |
| `keep_alive_timeout_sec` | int | `90` | 心跳保活超时（秒） |
| `reconnect_delay_sec` | int | `5` | 客户端重连基础间隔（秒） |
| `max_connections` | int | `100` | 服务端最大并发连接数 |
| `session_timeout_sec` | int | `300` | 服务端会话超时（秒） |
| `session_cleanup_interval_sec` | int | `30` | 服务端会话清理周期（秒） |
| `max_retries` | int | `10` | 客户端最大重连次数 |
| `heartbeat_interval_sec` | int | `30` | 心跳发送间隔（秒） |

### 服务端参考配置

```json
{
  "server_address": "0.0.0.0",
  "server_port": 8080,
  "cert_api_port": 8081,
  "network": "10.8.0.0/24",
  "server_ip": "10.8.0.1/24",
  "client_ip_start": 2,
  "client_ip_end": 254,
  "mtu": 1420,
  "keep_alive_timeout_sec": 90,
  "max_connections": 100,
  "session_timeout_sec": 300,
  "session_cleanup_interval_sec": 30,
  "enable_nat": true,
  "nat_interface": "eth0",
  "route_mode": "split",
  "push_routes": ["192.168.10.0/24"],
  "dns_servers": ["8.8.8.8", "8.8.4.4"],
  "redirect_gateway": false,
  "redirect_dns": false
}
```

### 客户端参考配置

```json
{
  "server_address": "vpn.example.com",
  "server_port": 8080,
  "network": "10.8.0.0/24",
  "mtu": 1420,
  "reconnect_delay_sec": 5,
  "route_mode": "split",
  "push_routes": [],
  "dns_servers": ["8.8.8.8"],
  "redirect_gateway": false,
  "redirect_dns": false
}
```

---

## 证书与 Token 机制

### 证书体系（自建 PKI）

```
自建 CA（RSA 4096，有效期 10 年）
  ├── 服务端证书（RSA 4096，1 年，CN=vpn-server，SAN=[localhost, vpn-server]）
  └── 客户端证书 × N（RSA 4096，1 年，CN=<clientName>，每客户端独立签发）
```

证书文件默认存储于 `./certs/` 目录：

| 文件 | 权限 | 说明 |
|------|------|------|
| `ca.pem` | 0644 | CA 公钥证书（可公开分发） |
| `ca-key.pem` | 0400 | CA 私钥（**仅服务端持有，严格保密**） |
| `server.pem` | 0644 | 服务端证书 |
| `server-key.pem` | 0600 | 服务端私钥 |
| `client.pem` | 0644 | 客户端证书 |
| `client-key.pem` | 0600 | 客户端私钥 |

### Token 机制

Token 是一次性授权凭证，同时作为 AES-256-GCM 对称密钥对 CSR 与证书进行端到端加密。

Token 文件存储于 `./tokens/` 目录，每个 Token 对应一个 JSON 文件（0600 权限）：

```json
{
  "id": "alice-20240101-120000",
  "client_name": "alice",
  "key_hex": "a3f2b1...（64位十六进制，即AES-256 key）",
  "created_at": "2024-01-01T12:00:00Z",
  "expires_at": "2024-01-08T12:00:00Z",
  "used": false,
  "used_at": null,
  "used_by": ""
}
```

### 证书申请完整流程

```
① 服务端管理员生成 Token（TokenID + TokenKey），通过安全渠道发送给客户端
② 客户端在本地生成 RSA 4096 私钥与 CSR（私钥不离开本机）
③ 客户端用 Token Key（AES-256-GCM）加密 CSR
④ POST http://server:8081/api/cert/request（附 TokenID + 密文 CSR）
⑤ 服务端验证 Token（存在 + 未过期 + 未使用）→ 立即标记 used=true
⑥ 服务端用 CA 私钥签发客户端证书，用 Token Key 加密证书与 CA 证书返回
⑦ 客户端解密，将以下文件写入 ./certs/：
     ca.pem          CA 证书
     client.pem      客户端证书
     client-key.pem  客户端私钥（从 CSR 生成目录复制）
⑧ Bootstrap 完成，Token 失效，后续使用 mTLS 建立 VPN 连接
```

**重要说明**：
- Token 为**单次使用**，使用后立即标记并持久化，重启服务端后仍不可重用
- 证书 API（8081）走明文 HTTP，但 payload 已由 AES-256-GCM 加密保护，中间人无法解密
- 客户端证书有效期 1 年，到期后需重新执行 Bootstrap 流程

---

## 网络行为详解

### 路由模式

#### split（分流，默认）

- 仅将 `push_routes` 中指定的网段路由至 TUN 接口
- 其余流量继续走宿主机原有默认网关
- 适合只需访问公司内网等特定网段的场景

#### full（全流量）

- 将默认路由（`0.0.0.0/0`）指向 TUN 接口，所有流量走 VPN
- `exclude_routes` 中的网段保持走原有网关（用于排除本地网络等）
- 通常与 `redirect_gateway=true`、`redirect_dns=true` 配合使用
- 服务端建议同时启用 `enable_nat=true`

### NAT 配置（Linux 服务端）

`enable_nat=true` 时，服务端自动配置以下 iptables 规则：

```
iptables -t nat -A POSTROUTING -s <vpnCIDR> -o <outIface> -j MASQUERADE
iptables -A FORWARD -i <tun> -o <outIface> -j ACCEPT
iptables -A FORWARD -i <outIface> -o <tun> -m state --state RELATED,ESTABLISHED -j ACCEPT
```

退出时自动删除所有已添加规则。若 `nat_interface` 为空，自动检测出口网卡。

### DNS 处理

| 平台 | 接管方式 | 恢复方式 |
|------|---------|---------|
| Linux | 备份 `/etc/resolv.conf` → 写入 VPN DNS | 从 `/etc/resolv.conf.vpn-backup` 恢复并删除备份 |
| Windows | `netsh interface ip set dns` | 恢复原 DNS 配置 |

VPN 断开时自动恢复原 DNS 配置。若无备份文件则安全跳过，不破坏系统 DNS。

### 数据包传输路径

```
[客户端进程] → [client TUN] → [TLS 1.3 加密] → [server TUN] → [内核转发/外网]
[外网/内网]  → [server TUN] → [TLS 1.3 加密] → [client TUN] → [客户端进程]
```

应用层消息格式（5 字节固定帧头）：

```
+--------+-------------------+------------------+
| Type   | Length (4B, BE)   | Payload（变长）  |
| 1 byte | 4 bytes big-endian| Length 字节      |
+--------+-------------------+------------------+
```

消息类型：`IPAssignment`（IP 分配）、`Control`（配置推送）、`Data`（IP 包数据）、`Heartbeat`（心跳）

---

## TUI 菜单总览

```
主菜单
├── 1. 服务端模式
│   ├── 启动 / 停止服务端
│   ├── 服务端参数设置（端口、网段、MTU、连接上限）
│   ├── 路由模式与 DNS 设置
│   ├── CA 证书管理（初始化、查看、重新生成）
│   ├── Token 管理（生成、列表、删除、清理过期）
│   ├── 在线客户端（查看连接列表、踢出、流量统计）
│   └── 实时日志查看
│
├── 2. 客户端模式
│   ├── 连接 / 断开 VPN
│   ├── 设置服务端地址与端口
│   ├── 生成 CSR（含客户端私钥）
│   ├── 使用 Token 申请证书
│   ├── 查看连接状态（虚拟 IP、服务端地址、流量）
│   └── 查看证书状态（有效期、颁发者）
│
├── 3. 配置管理
│   ├── 保存当前配置
│   ├── 从文件加载配置
│   ├── 查看当前配置（JSON）
│   └── 恢复默认配置
│
├── 4. 快速向导
│   ├── 服务端快速部署
│   │   端口 → 网段 → 路由模式 → 证书初始化 → 启动服务 → （可选）生成 Token
│   └── 客户端快速配置
│       地址 → 端口 → 检查证书 → 申请证书 → 连接 VPN
│
└── 5. 退出（仅退出 TUI，后台服务继续运行）
```

---

## 项目结构

```
tls-vpn/
├── README.md
├── source/
│   ├── go.mod
│   ├── go.sum
│   │
│   ├── 入口与编排
│   │   ├── main.go                  程序入口，命令分发，智能启动
│   │   ├── vpn_service.go           领域服务层，编排所有子系统生命周期
│   │   └── config.go                配置结构体、默认值、JSON 加载/写回
│   │
│   ├── VPN 数据面
│   │   ├── vpn_server.go            mTLS 服务端、IP 池分配、TUN 转发、会话管理
│   │   ├── vpn_client.go            mTLS 客户端、握手状态机、路由设置、心跳重连
│   │   ├── tun_interface.go         TUN 设备跨平台抽象接口
│   │   ├── tun_device_unix.go       Linux/macOS TUN 实现（songgao/water 库封装）
│   │   └── tun_device_windows.go    Windows TUN 实现（Wintun + ring buffer）
│   │
│   ├── 网络配置
│   │   ├── ip_pool.go               虚拟 IP 地址池（分配/回收/过期）
│   │   ├── route_manager.go         Unix 路由管理（ip route 命令）
│   │   ├── route_manager_windows.go Windows 路由管理（route ADD 命令）
│   │   └── iptables_nat.go          Linux NAT 规则（MASQUERADE + FORWARD）
│   │
│   ├── 证书与身份
│   │   ├── cert_manager.go          自建 CA、证书生成/加载、TLS 配置
│   │   └── cert_api_server.go       HTTP 8081：接收 CSR、验证 Token、签发证书
│   │
│   ├── Token 体系
│   │   ├── token_manager.go         Token 元数据管理（生成/验证/单次标记）
│   │   ├── token_crypto.go          AES-256-GCM 加密/解密
│   │   └── token_file.go            Token 落盘（0600 权限 JSON 文件）
│   │
│   ├── 控制面与协议
│   │   ├── control_server.go        本地控制 API 服务端（Unix Socket）
│   │   ├── control_client.go        控制 API 客户端（TUI 侧 IPC）
│   │   ├── protocol_message.go      数据通道消息帧定义与编解码（5 字节帧头）
│   │   └── api_protocol.go          控制 API 请求/响应结构定义
│   │
│   ├── 平台适配
│   │   ├── daemon_unix.go           Unix 后台进程启动（Setsid）
│   │   ├── daemon_windows.go        Windows 后台进程启动（HideWindow）
│   │   ├── signal_unix.go           SIGINT/SIGTERM 信号处理
│   │   ├── signal_windows.go        os.Interrupt 信号处理
│   │   ├── constants_unix.go        Unix 平台路径常量（Socket、日志路径等）
│   │   └── constants_windows.go     Windows 平台路径常量
│   │
│   └── TUI 界面
│       ├── tui_app.go               TUI 主循环与全局状态
│       ├── tui_handlers.go          UI 事件 → IPC 业务命令
│       ├── tui_menus.go             菜单树与快捷键导航
│       ├── tui_dialogs.go           输入框、确认框、错误弹窗
│       └── tui_theme.go             配色与组件样式
│
└── build/                           编译产出目录
    ├── tls-vpn                      Linux 可执行文件
    └── tls-vpn.exe                  Windows 可执行文件
```

运行时自动生成：

```
./certs/        证书目录（ca.pem、server.pem、client.pem 等）
./tokens/       Token 目录（每个 Token 一个 .json 文件）
./config.json   配置文件
```

---

## 日志与运行状态

### 控制 Socket 路径

| 平台 | 路径 |
|------|------|
| Linux | `/var/run/vpn_control.sock` |
| Windows | `%TEMP%\vpn_control.sock` |

### 日志文件路径

| 平台 | 路径 |
|------|------|
| Linux | `/var/log/tls-vpn.log` |
| Windows | 可执行文件同目录下 `tls-vpn.log` |

日志自动轮转：单文件最大 10 MB，保留最近 5 个备份（`.log.1` ~ `.log.5`）。

### 运维命令速查

**Linux**

```bash
# 前台启动（自动拉起后台 + TUI）
sudo ./build/tls-vpn

# 仅启动后台服务
sudo ./build/tls-vpn --service

# 查看服务状态
./build/tls-vpn --status

# 停止服务
./build/tls-vpn --stop

# 实时查看日志
tail -f /var/log/tls-vpn.log
```

**Windows（管理员 PowerShell）**

```powershell
# 前台启动
.\build\tls-vpn.exe

# 仅启动后台服务
.\build\tls-vpn.exe --service

# 查看状态
.\build\tls-vpn.exe --status

# 停止服务
.\build\tls-vpn.exe --stop
```

### `--status` 输出内容

- 后台服务是否运行
- 服务端状态（监听端口、在线客户端数、TUN 接口、收发流量）
- 客户端状态（连接状态、分配的虚拟 IP、服务端地址）
- 当前生效配置（JSON 格式）

---

## 故障排查

### 后台服务无法启动

| 检查项 | 说明 |
|--------|------|
| 权限 | Linux 需要 root 或 `CAP_NET_ADMIN`；Windows 需要管理员权限 |
| Socket 残留 | Linux：删除 `/var/run/vpn_control.sock` 后重试 |
| 日志文件权限 | 确认 `/var/log/` 目录可写 |
| 端口占用 | 检查 8080、8081 端口是否被其他程序占用 |

### 客户端连接失败

| 可能原因 | 排查方式 |
|---------|---------|
| 地址或端口错误 | 检查 `server_address` 和 `server_port` 配置 |
| 服务端未启动 | 执行 `./build/tls-vpn --status` 确认服务端状态 |
| 防火墙未放行 | 确认 8080/tcp 已在服务端开放 |
| 客户端缺少证书 | 确认 `./certs/` 下存在 `ca.pem`、`client.pem`、`client-key.pem` |
| 证书已过期 | 证书有效期 1 年，到期后重新执行 Bootstrap |

### 证书申请失败

| 可能原因 | 排查方式 |
|---------|---------|
| 8081 端口未开放 | 检查服务端防火墙规则 |
| Token 已过期 | 服务端重新生成 Token |
| Token 已被使用 | Token 为单次使用，需生成新 Token |
| Token 格式错误 | 确认输入格式为 `TokenID:TokenKey`（64 位十六进制 Key） |
| CSR 文件不存在 | 先执行"生成 CSR"步骤 |

### 连上 VPN 但无法访问外网

| 可能原因 | 排查方式 |
|---------|---------|
| 服务端未启用 NAT | 确认 `enable_nat=true`，查看日志中 NAT 规则是否添加成功 |
| `nat_interface` 配置错误 | 在服务端执行 `ip route` 确认出口网卡名称，更新配置 |
| IP 转发未开启 | 执行 `cat /proc/sys/net/ipv4/ip_forward` 确认值为 `1` |
| 路由模式不正确 | full 模式需要 `redirect_gateway=true` + NAT 同时启用 |

### DNS 解析异常

| 可能原因 | 排查方式 |
|---------|---------|
| `redirect_dns` 未启用 | 在配置中设置 `redirect_dns=true` |
| `dns_servers` 格式错误 | 确认为有效 IPv4 地址列表 |
| Linux resolv.conf 不可写 | 检查 `/etc/resolv.conf` 文件权限 |
| 备份文件残留 | 如有残留的 `/etc/resolv.conf.vpn-backup`，手动检查内容并决定是否恢复 |

---

## 安全建议

1. **保护 CA 私钥**：`ca-key.pem` 以 0400 权限存储，确保只有运行用户可读；生产环境建议使用 HSM 或将 CA 离线保存
2. **限制证书 API 访问**：对 8081 端口设置来源 IP 白名单，仅允许需要申请证书的客户端 IP 访问；客户端完成证书申请后可临时关闭该端口
3. **Token 安全传输**：通过加密渠道（Signal、GPG 加密邮件等）传输 TokenID:TokenKey，避免明文传输
4. **定期清理 Token**：定期在 TUI 中清理过期和已使用的 Token，减少攻击面
5. **配置文件权限**：`config.json` 以 0600 权限保存，避免其他用户读取服务端地址等信息
6. **证书续期**：客户端和服务端证书有效期均为 1 年，提前安排证书更新（重新执行 Bootstrap）
7. **不要分发 CA 私钥**：`ca-key.pem` 只应在服务端机器上存在，切勿发送给任何客户端
8. **最小权限运行**：Linux 上建议仅授予 `CAP_NET_ADMIN` 而非完整 root 权限运行 VPN 进程

---

## 开发参考

### 核心依赖

```
github.com/rivo/tview        TUI 框架
github.com/gdamore/tcell/v2  终端控制
github.com/songgao/water     TUN/TAP 设备（Linux）
golang.zx2c4.com/wireguard   Wintun 驱动（Windows TUN）
```

### 控制 API Action 列表

| 分类 | Action | 说明 |
|------|--------|------|
| 系统 | `ping` | 探活，确认服务是否运行 |
| 系统 | `shutdown` | 优雅停止服务 |
| 服务端 | `server/start` | 启动 VPN 服务端 |
| 服务端 | `server/stop` | 停止 VPN 服务端 |
| 服务端 | `server/status` | 获取服务端状态（端口、客户端数、流量） |
| 服务端 | `server/clients` | 获取在线客户端列表 |
| 服务端 | `server/kick` | 踢出指定客户端 |
| 客户端 | `client/connect` | 连接 VPN |
| 客户端 | `client/disconnect` | 断开 VPN |
| 客户端 | `client/status` | 获取客户端连接状态 |
| 证书 | `cert/init-ca` | 初始化 CA 与服务端证书 |
| 证书 | `cert/gen-csr` | 生成 CSR 与客户端私钥 |
| 证书 | `cert/request` | 使用 Token 申请证书 |
| 证书 | `cert/status` | 查看证书状态 |
| Token | `token/generate` | 生成新 Token |
| Token | `token/list` | 列出所有 Token |
| Token | `token/delete` | 删除指定 Token |
| Token | `token/cleanup` | 清理过期/已使用 Token |
| 配置 | `config/get` | 获取当前配置 |
| 配置 | `config/update` | 更新配置 |
| 配置 | `config/save` | 保存配置到文件 |
| 配置 | `config/load` | 从文件加载配置 |
| 日志 | `log/fetch` | 增量拉取日志（TUI 实时显示） |

### 二次开发说明

**新增配置项**时需同步修改：
1. `config.go`：`VPNConfig` 结构体 + `DefaultConfig`
2. `vpn_service.go` / `vpn_server.go` / `vpn_client.go`：读取新字段的业务逻辑
3. TUI 设置入口（`tui_handlers.go` / `tui_menus.go`）
4. README 配置字段说明表

**扩展控制 API** 时需同步修改：
- `api_protocol.go`：新增 Action 常量与请求/响应结构
- `control_server.go`：注册新 Action 的处理函数
- `control_client.go`：新增客户端调用方法

**关键耦合点**：客户端 `tlsConfig.ServerName = "vpn-server"` 与服务端证书 `DNSNames = ["localhost", "vpn-server"]` 强耦合——若需通过 IP 直连服务端，必须在服务端证书的 `IPAddresses` 字段中添加对应 IP，并同步修改客户端 `ServerName`。
