# TLS VPN 系统

[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)](https://golang.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-blue.svg)](#-系统要求)

一个基于 **TLS 1.3 + TUN(L3) 隧道** 的跨平台 VPN 系统，使用 Go 开发，支持：

- 服务端/客户端双模式
- 交互式 TUI 管理界面
- 后台守护进程（Daemon）
- 证书体系（CA/服务端/客户端）
- Token 驱动的安全证书申请
- 路由分流 / 全局转发（NAT）

---

## 目录

- [1. 项目定位](#1-项目定位)
- [2. 核心特性](#2-核心特性)
- [3. 运行模式与启动逻辑](#3-运行模式与启动逻辑)
- [4. 架构与模块说明](#4-架构与模块说明)
- [5. 系统要求](#5-系统要求)
- [6. 编译与构建](#6-编译与构建)
- [7. 快速开始](#7-快速开始)
- [8. 配置文件完整说明](#8-配置文件完整说明)
- [9. 证书与 Token 机制](#9-证书与-token-机制)
- [10. 网络行为（路由 / NAT / DNS）](#10-网络行为路由--nat--dns)
- [11. TUI 菜单总览](#11-tui-菜单总览)
- [12. 目录与文件说明](#12-目录与文件说明)
- [13. 日志、Socket 与运行状态](#13-日志socket-与运行状态)
- [14. 常见运维命令](#14-常见运维命令)
- [15. 故障排查](#15-故障排查)
- [16. 安全建议](#16-安全建议)
- [17. 开发说明](#17-开发说明)
- [18. 内部架构参考（英文）](#18-内部架构参考英文)

---

## 1. 项目定位

本项目适合以下场景：

1. 需要自建轻量 VPN（不依赖 OpenVPN/WireGuard 守护进程）
2. 希望通过 TUI 快速完成服务端部署和客户端接入
3. 需要跨 Linux / Windows 的统一代码与运维体验
4. 需要可控的证书签发流程（Token 单次授权）

本项目不是内核级 VPN 协议重实现，而是基于用户态 TLS 隧道 + TUN 设备实现 L3 传输。

---

## 2. 核心特性

### 2.1 安全与认证

- 强制 TLS 1.3 连接
- 双向证书认证（mTLS）
- CA 自管理（自动生成 CA、服务端证书）
- 客户端证书通过 Token 申请并加密传输
- Token 支持：有效期、单次使用、状态持久化

### 2.2 网络能力

- 基于 TUN 的三层 VPN 隧道
- 会话管理 + 心跳保活
- 客户端自动重连
- 路由模式：
  - `split`（分流）
  - `full`（全流量）
- DNS 推送与可选 DNS 劫持
- Linux 服务端自动配置 iptables NAT/FORWARD（可开关）

### 2.3 运维与可视化

- 交互式 TUI（菜单化管理）
- 智能启动（自动拉起后台服务 + 连接 TUI）
- 后台控制通道（Unix Socket，本地 IPC）
- 配置可保存/加载/重置
- 在线客户端查看、踢出、流量统计

---

## 3. 运行模式与启动逻辑

程序入口支持以下命令：

```bash
./tls-vpn
./tls-vpn --service
./tls-vpn --status
./tls-vpn --stop
./tls-vpn --help
```

### 3.1 默认模式（推荐）

执行 `./tls-vpn` 时：

1. 检测后台服务是否已运行
2. 若未运行，自动 fork/创建 `--service` 进程
3. 等待控制 API 就绪
4. 启动 TUI，后续通过 IPC 控制后台服务

### 3.2 后台服务模式

执行 `./tls-vpn --service`：

- 只启动后台服务，不进入 TUI
- 启动控制 API Server（本地 Socket）
- 持有 VPNService，供 TUI 或 CLI 状态命令调用

### 3.3 状态与停止

- `--status`：读取服务端/客户端状态并打印当前配置
- `--stop`：通过控制 API 发出 `shutdown`

---

## 4. 架构与模块说明

### 4.1 总体架构

```text
TUI (前台)
   │
   │ Unix Socket IPC
   ▼
Control Server (后台)
   │
   ▼
VPNService
 ├─ VPNServer
 ├─ VPNClient
 ├─ CertAPIServer (HTTP, 默认8081)
 ├─ CertificateManager
 └─ Config/Token 管理
```

### 4.2 关键源码模块

- `source/main.go`：程序入口、参数分发、智能启动
- `source/vpn_service.go`：核心业务层，统一协调服务端/客户端/证书/Token/配置
- `source/vpn_server.go`：服务端 TLS 接入、会话管理、TUN 转发
- `source/vpn_client.go`：客户端连接、重连、路由/DNS下发应用
- `source/cert_manager.go`：CA/证书生成与加载
- `source/cert_api_server.go`：证书申请 HTTP API（`/api/cert/request`）
- `source/token_manager.go`：Token 内存与文件管理
- `source/control_server.go` / `source/control_client.go`：本地控制协议
- `source/tui_*.go`：界面、菜单、交互处理

---

## 5. 系统要求

### 5.1 通用要求

- Go 1.24+
- 具备管理员权限（Windows）或 root/CAP_NET_ADMIN（Linux）
- 能创建 TUN 设备

### 5.2 Linux

- `ip` 命令（iproute2）
- `iptables`（若启用 NAT）
- 建议可写 `/var/run`、`/var/log`

### 5.3 Windows

- Windows 10/11（建议）
- 需管理员权限运行
- 使用 WireGuard 的 `wintun` 组件（通过 Go 依赖引入）

---

## 6. 编译与构建

> 源码在 `source/` 目录，建议在该目录执行构建命令。

### 6.1 本机构建

```bash
cd source
go mod download
go build -o ../bin/tls-vpn
```

Windows PowerShell 示例：

```powershell
Set-Location .\source
go mod download
go build -o ..\bin\tls-vpn.exe
```

### 6.2 交叉编译

Linux -> Windows：

```bash
cd source
GOOS=windows GOARCH=amd64 go build -o ../bin/tls-vpn.exe
```

Windows -> Linux（PowerShell）：

```powershell
Set-Location .\source
$env:GOOS="linux"
$env:GOARCH="amd64"
go build -o ..\bin\tls-vpn
```

---

## 7. 快速开始

### 7.1 一机体验（本机启动）

```bash
# Linux
sudo ./bin/tls-vpn

# Windows（管理员PowerShell）
.\bin\tls-vpn.exe
```

进入 TUI 后可直接使用“快速向导”：

- 服务端快速部署（初始化证书 + 启动服务）
- 客户端快速配置（地址端口 + 证书申请 + 连接）

### 7.2 典型生产流程（两台机器）

#### A. 服务端机器

1. 启动程序进入 TUI
2. 执行 `服务端快速部署`
3. 生成一个或多个 Token
4. 将 Token（`ID:KEY`）安全发送给客户端
5. 开放 VPN 端口（默认 `8080`）和证书 API 端口（默认 `8081`）

#### B. 客户端机器

1. 启动程序进入 TUI
2. 设置服务端地址与端口
3. 生成 CSR
4. 使用 Token 申请证书
5. 连接 VPN

---

## 8. 配置文件完整说明

默认配置文件路径：`./config.json`

程序会在启动时尝试加载该文件；配置更新后会自动保存。

### 8.1 字段总表

| 字段                             | 类型         | 默认值               | 说明                               |
| -------------------------------- | ------------ | -------------------- | ---------------------------------- |
| `server_address`               | string       | `localhost`        | 客户端连接的服务端地址             |
| `server_port`                  | int          | `8080`             | VPN TLS 监听端口                   |
| `client_address`               | string       | `10.8.0.2/24`      | 预留字段（当前主要由服务端分配IP） |
| `network`                      | string(CIDR) | `10.8.0.0/24`      | VPN 网段                           |
| `mtu`                          | int          | `1500`             | TUN MTU（576~9000）                |
| `keep_alive_timeout_sec`       | int          | `90`               | 保活超时                           |
| `reconnect_delay_sec`          | int          | `5`                | 客户端重连间隔                     |
| `max_connections`              | int          | `100`              | 服务端最大并发连接                 |
| `session_timeout_sec`          | int          | `300`              | 会话超时                           |
| `session_cleanup_interval_sec` | int          | `30`               | 会话清理周期                       |
| `server_ip`                    | string(CIDR) | `10.8.0.1/24`      | 服务端 VPN 地址                    |
| `client_ip_start`              | int          | `2`                | 客户端地址池起始                   |
| `client_ip_end`                | int          | `254`              | 客户端地址池结束                   |
| `dns_servers`                  | []string     | `8.8.8.8, 8.8.4.4` | 推送 DNS                           |
| `push_routes`                  | []string     | `[]`               | 分流模式下推送路由                 |
| `route_mode`                   | string       | `split`            | `split`/`full`                 |
| `exclude_routes`               | []string     | `[]`               | 全局模式排除路由                   |
| `redirect_gateway`             | bool         | `false`            | 是否重定向默认网关                 |
| `redirect_dns`                 | bool         | `false`            | 是否启用 DNS 劫持                  |
| `enable_nat`                   | bool         | `true`             | 服务端 NAT 开关                    |
| `nat_interface`                | string       | `""`               | NAT 出口网卡，空=自动检测          |

### 8.2 服务端参考配置

```json
{
  "server_address": "0.0.0.0",
  "server_port": 8080,
  "network": "10.8.0.0/24",
  "server_ip": "10.8.0.1/24",
  "client_ip_start": 2,
  "client_ip_end": 254,
  "mtu": 1500,
  "keep_alive_timeout_sec": 90,
  "max_connections": 100,
  "session_timeout_sec": 300,
  "session_cleanup_interval_sec": 30,
  "enable_nat": true,
  "nat_interface": "eth0",
  "route_mode": "split",
  "redirect_gateway": false,
  "redirect_dns": false,
  "push_routes": ["192.168.10.0/24"],
  "dns_servers": ["8.8.8.8", "8.8.4.4"]
}
```

### 8.3 客户端参考配置

```json
{
  "server_address": "vpn.example.com",
  "server_port": 8080,
  "network": "10.8.0.0/24",
  "mtu": 1500,
  "reconnect_delay_sec": 5,
  "route_mode": "split",
  "redirect_gateway": false,
  "redirect_dns": false,
  "push_routes": [],
  "dns_servers": ["8.8.8.8"]
}
```

---

## 9. 证书与 Token 机制

### 9.1 证书文件

默认目录：`./certs`

- `ca.pem`：CA 公钥证书
- `ca-key.pem`：CA 私钥（仅服务端需要）
- `server.pem` / `server-key.pem`：服务端证书与私钥
- `client.pem` / `client-key.pem`：客户端证书与私钥

### 9.2 Token 文件

默认目录：`./tokens`

每个 Token 对应一个 `.json` 文件，包含：

- `id`
- `key_hex`
- `client_name`
- `created_at`
- `expires_at`
- `used` / `used_at` / `used_by`

### 9.3 申请证书的完整流程

1. 客户端生成 CSR 与私钥（当前目录产生 `*.csr` 与 `*-key.pem`）
2. 客户端携带 Token 对 CSR 进行加密
3. 请求服务端证书 API：`POST http://<server>:8081/api/cert/request`
4. 服务端验证 Token（存在、未过期、未使用）
5. 服务端签发客户端证书并加密返回
6. 客户端解密并写入：
   - `./certs/client.pem`
   - `./certs/client-key.pem`
   - `./certs/ca.pem`

### 9.4 重要注意

- Token 为**单次使用**，使用后自动标记 `used`
- 证书 API 默认监听 `8081`（与 VPN 数据通道端口 `8080` 不同）
- 客户端申请证书阶段需要能访问服务端 `8081`

---

## 10. 网络行为（路由 / NAT / DNS）

### 10.1 路由模式

#### `split`（分流）

- 默认推荐
- 仅将推送网段导入 VPN 路由
- 未匹配流量继续走本地默认网关

#### `full`（全局）

- 将默认路由导向 VPN
- 常与 `redirect_gateway=true`、`redirect_dns=true` 配合
- 服务端建议启用 NAT（`enable_nat=true`）

### 10.2 NAT（Linux 服务端）

当启用 NAT 时，服务端会尝试：

1. `iptables -t nat -A POSTROUTING ... MASQUERADE`
2. 添加 FORWARD 规则（TUN 出口双向）

若 NAT 配置失败，服务端仍可启动，但客户端可能无法访问外网。

### 10.3 DNS 处理

- Linux：通过修改 `/etc/resolv.conf`，并创建备份再恢复
- Windows：通过 `netsh` 调整接口 DNS
- 断开 VPN 时会尝试恢复原 DNS

---

## 11. TUI 菜单总览

主菜单包含：

1. 服务端模式
2. 客户端模式
3. 配置管理
4. 快速向导
5. 退出

### 11.1 服务端模式

- 启动/停止服务端
- 服务端参数设置（端口、网段、MTU、连接上限）
- 路由模式与 DNS 设置
- CA 证书管理
- Token 管理
- 在线客户端查看 / 踢出
- 流量统计

### 11.2 客户端模式

- 连接 / 断开 VPN
- 设置服务端地址与端口
- 生成 CSR
- 使用 Token 申请证书
- 查看连接状态与证书状态

### 11.3 配置管理

- 保存配置
- 加载配置
- 查看配置
- 恢复默认配置

### 11.4 快速向导

- 服务端快速部署：端口、网段、路由模式、证书初始化、启动服务、可选生成 Token
- 客户端快速配置：地址、端口、证书检查、申请证书、连接 VPN

---

## 12. 目录与文件说明

```text
tls-vpn/
├─ README.md
└─ source/
   ├─ main.go
   ├─ vpn_service.go
   ├─ vpn_server.go
   ├─ vpn_client.go
   ├─ cert_manager.go
   ├─ cert_api_server.go
   ├─ token_manager.go
   ├─ token_crypto.go
   ├─ control_server.go
   ├─ control_client.go
   ├─ tui_*.go
   ├─ route_manager*.go
   ├─ tun_device_*.go
   ├─ iptables_nat.go
   ├─ config.go / config.json
   └─ go.mod
```

运行时还会生成：

- `./certs/`：证书目录
- `./tokens/`：Token目录
- 日志文件（平台相关，见下文）

---

## 13. 日志、Socket 与运行状态

### 13.1 控制 Socket

- Linux：`/var/run/vpn_control.sock`
- Windows：`%TEMP%\vpn_control.sock`

### 13.2 默认日志路径

- Linux：`/var/log/tls-vpn.log`
- Windows：可执行文件同目录下 `tls-vpn.log`

### 13.3 状态查询

```bash
./tls-vpn --status
```

可查看：

- 服务是否运行
- 服务端状态（端口、客户端数量、TUN、流量）
- 客户端状态（连接、分配IP、服务端地址）
- 当前配置 JSON

---

## 14. 常见运维命令

### 14.1 Linux

```bash
# 前台启动（自动拉起后台服务 + TUI）
sudo ./tls-vpn

# 仅后台服务
sudo ./tls-vpn --service

# 查看状态
./tls-vpn --status

# 停止
./tls-vpn --stop

# 查看日志
tail -f /var/log/tls-vpn.log
```

### 14.2 Windows（管理员 PowerShell）

```powershell
# 前台启动
.\tls-vpn.exe

# 仅后台服务
.\tls-vpn.exe --service

# 查看状态
.\tls-vpn.exe --status

# 停止
.\tls-vpn.exe --stop
```

---

## 15. 故障排查

### 15.1 后台服务无法启动

检查：

1. 是否具备管理员/root权限
2. 控制 Socket 是否残留（Linux：`/var/run/vpn_control.sock`）
3. 日志文件是否可写

### 15.2 客户端连接失败

常见原因：

- 地址/端口错误（`server_address` / `server_port`）
- 服务端未启动
- 防火墙未放行 `8080`
- 客户端缺失 `ca.pem`/`client.pem`/`client-key.pem`

### 15.3 证书申请失败

重点检查：

1. 服务端 `8081` 是否开放
2. Token 是否过期/已使用
3. Token `ID:KEY` 是否完整
4. CSR 文件是否存在且可读

### 15.4 能连上 VPN 但不能访问外网

- 检查服务端是否启用 NAT
- 检查 Linux `iptables` 规则是否成功写入
- 检查 `nat_interface` 是否正确

### 15.5 DNS 异常

- 检查 `redirect_dns` 是否启用
- 检查 `dns_servers` 格式是否正确
- Linux 下确认 `/etc/resolv.conf` 权限与可写性

---

## 16. 安全建议

1. 生产环境请限制证书目录权限（尤其 `ca-key.pem`）
2. Token 请通过安全信道传输，避免明文聊天工具长期存档
3. 建议定期清理过期/已使用 Token
4. 不建议将 `ca-key.pem` 分发到客户端
5. 建议对 `8081` 做来源 IP 限制或临时开放

---

## 17. 开发说明

### 17.1 依赖

核心依赖（见 `source/go.mod`）：

- `github.com/rivo/tview`
- `github.com/gdamore/tcell/v2`
- `github.com/songgao/water`
- `golang.zx2c4.com/wireguard`

### 17.2 控制 API Action（节选）

- 服务端：`server/start`、`server/stop`、`server/status`
- 客户端：`client/connect`、`client/disconnect`、`client/status`
- 证书：`cert/init-ca`、`cert/gen-csr`、`cert/request`
- Token：`token/generate`、`token/list`、`token/delete`
- 配置：`config/get`、`config/update`、`config/save`、`config/load`
- 系统：`ping`、`shutdown`

### 17.3 二次开发建议

- 新增配置项时同步更新：
  - `VPNConfig`
  - `ConfigFile` JSON 映射
  - TUI 设置入口
  - README 字段表
- 若扩展 API，请保持 `api_protocol.go` 与 `control_server.go` 同步

---

## 18. 内部架构参考（英文）

详细的英文内部架构文档位于 [`docs/INTERNALS.md`](docs/INTERNALS.md)，涵盖：

- 证书管理与签发流程（CA 初始化、CSR 生成、Token 验证、证书签发）
- Token 系统（生成、存储格式、AES-256-GCM 加密、单次使用机制）
- 控制平面协议（Unix Socket 帧格式、Actions 全表、并发模型、关闭语义）
- 数据平面协议（13 字节帧头、消息类型、序列号/校验和、与 TLS 1.3 的关系）
- 平台差异（Linux vs Windows：TUN 设备、路由管理、DNS 处理、Socket 路径、日志）
- 配置管理（加载/保存/重置/更新、字段验证、冷应用语义）
- 可观测性与运维（日志架构、文件轮转、TUI 日志流、错误处理模式）

该文档适合学术报告引用，所有代码引用均附有到 `main` 分支的永久链接。
