# TLS-VPN — Internal Architecture Reference

> **Audience:** developers, security researchers, and academic readers who need a precise, code-grounded description of every major subsystem.  All source-code references are permalinks to commit `0b4aeb078ef20f99df212e765cab14c4b6a55145` on the `main` branch.  When significant code changes are made, update this hash and re-verify each permalink.

---

## Table of Contents

1. [Certificate Management and Issuance Flow](#1-certificate-management-and-issuance-flow)
2. [Token System](#2-token-system)
3. [Control Plane Protocol](#3-control-plane-protocol)
4. [Data Plane Protocol](#4-data-plane-protocol)
5. [Platform Differences](#5-platform-differences)
6. [Configuration Management](#6-configuration-management)
7. [Observability and Operations](#7-observability-and-operations)

---

## 1. Certificate Management and Issuance Flow

### 1.1 Overview

The certificate subsystem implements a self-contained PKI that issues an RSA-4096 CA, a server leaf certificate, and per-client leaf certificates.  Client certificates are **never** generated server-side in advance; they are issued on-demand through a token-authenticated HTTP API ([`cert_api_server.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/cert_api_server.go)).

### 1.2 CA Initialisation

When `VPNService.StartServer()` is called and no server certificates exist in `./certs/`, `NewCertificateManager()` ([`cert_manager.go:449`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/cert_manager.go#L449)) runs the following sequence:

1. **Generate CA key-pair** — `generateCACertificate()` ([`cert_manager.go:33`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/cert_manager.go#L33)):
   - RSA-4096 private key via `crypto/rand`.
   - 128-bit cryptographically random serial number.
   - X.509 `IsCA=true`, `BasicConstraintsValid=true`, validity 10 years.
   - `KeyUsage`: `KeyEncipherment | DigitalSignature | CertSign`.
   - `ExtKeyUsage`: `ServerAuth | ClientAuth` (broad, covering both roles).
   - Subject: `O=SecureVPN Organization / C=CN / L=Beijing / CN=VPN-CA`.

2. **Generate server leaf certificate** — `generateCertificatePair(isServer=true, ...)` ([`cert_manager.go:79`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/cert_manager.go#L79)):
   - RSA-4096 key.
   - Validity 1 year.
   - `ExtKeyUsage`: `ServerAuth` only.
   - `DNSNames`: `["localhost", "vpn-server"]`; `IPAddresses`: `[127.0.0.1]`.
   - `CN=vpn-server` (must match the TLS `ServerName` set by the client, see §4).

3. **Persist to disk** — `SaveServerCertificates()` / `SaveCAKey()` ([`cert_manager.go:255`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/cert_manager.go#L255), [`cert_manager.go:300`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/cert_manager.go#L300)):

   | File | Mode | Notes |
   |------|------|-------|
   | `./certs/ca.pem` | 0644 | CA certificate (public) |
   | `./certs/server.pem` | 0644 | Server leaf certificate |
   | `./certs/server-key.pem` | 0600 | Server private key |
   | `./certs/ca-key.pem` | 0400 | CA private key — read-only, owner only |

4. **Load into memory** — An in-memory `CertificateManager` is returned, holding the server `tls.Certificate` and a `*x509.CertPool` for client verification.

If certificates already exist, step 1–3 are skipped and `LoadServerCertificateManager()` ([`cert_manager.go:329`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/cert_manager.go#L329)) reads them directly.

### 1.3 Client CSR Generation

On the client side, the TUI action `cert/gen-csr` triggers `VPNService.GenerateCSR(clientName)`, which:

1. Generates a fresh RSA-4096 private key.
2. Builds an `x509.CertificateRequest` with `CN=<clientName>` and `ExtKeyUsage: ClientAuth`.
3. Signs the CSR with the private key (`x509.CreateCertificateRequest`).
4. Writes `<clientName>-<timestamp>.csr` and `<clientName>-key.pem` to the working directory (mode 0600 for the key).
5. Returns the file paths to the TUI ([`api_protocol.go:154`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/api_protocol.go#L154)).

### 1.4 Token-Authenticated Certificate Request

The HTTP endpoint `POST /api/cert/request` ([`cert_api_server.go:96`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/cert_api_server.go#L96)) handles client certificate issuance:

```
Client                                     CertAPIServer (port 8081)
  |                                               |
  |-- POST /api/cert/request ------------------>  |
  |   {token_id, encrypted_csr, nonce}            |
  |                                               |-- ValidateAndUseToken(token_id)
  |                                               |-- DecryptWithToken(encrypted_csr, nonce, key)
  |                                               |-- x509.ParseCertificateRequest(csr)
  |                                               |-- csr.CheckSignature()
  |                                               |-- signCertificate(csr)   [1-year validity]
  |                                               |-- EncryptWithToken(cert, key)
  |                                               |-- EncryptWithToken(ca_cert, key)
  |<-- {encrypted_cert, encrypted_ca, nonce, ---- |
  |     ca_nonce}                                  |
```

**Validation steps performed by the server (in order):**

1. `token_id` must exist in `TokenManager` (in-memory map).
2. Token must not be marked `Used`.
3. Token `ExpiresAt` must be in the future.
4. Token is marked `Used`, `UsedAt`, `UsedBy` (client IP) — atomic write under `sync.Mutex`.
5. Used state is immediately flushed to `./tokens/<id>.json` (0600).
6. CSR PEM is decrypted with the token's AES-256 key.
7. CSR self-signature is verified with `csr.CheckSignature()`.
8. Server signs the CSR with `ca-key.pem`, setting `ExtKeyUsage: ClientAuth`, 1-year validity, fresh 128-bit serial.

**Client-side processing after response:**

The client decrypts both `encrypted_cert` and `encrypted_ca` using the same token key/nonces, then writes:
- `./certs/client.pem` (0644)
- `./certs/client-key.pem` (0600)
- `./certs/ca.pem` (0644)

After this step the client holds all material needed for mTLS.

### 1.5 TLS Configuration

| Side | Config | Reference |
|------|--------|-----------|
| Server | `tls.RequireAndVerifyClientCert`, CA pool for client verification, TLS 1.3 only | [`cert_manager.go:511`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/cert_manager.go#L511) |
| Client | CA pool for server verification, `ServerName="vpn-server"`, TLS 1.3 only | [`cert_manager.go:522`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/cert_manager.go#L522) |

Both sides pin `MinVersion = MaxVersion = tls.VersionTLS13`, preventing any downgrade.

---

## 2. Token System

### 2.1 Token Structure

A `Token` ([`token_manager.go:16`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/token_manager.go#L16)) serves a dual purpose: it is both an **authentication credential** and an **AES-256 symmetric encryption key**.

```go
type Token struct {
    ID         string    // e.g. "alice-20240101-120000"
    Key        []byte    // 32 bytes, never serialised to JSON (tag: "-")
    ClientName string
    CreatedAt  time.Time
    ExpiresAt  time.Time
    Used       bool
    UsedAt     time.Time
    UsedBy     string    // IP address of consumer
}
```

### 2.2 Token Generation

`TokenManager.GenerateToken(clientName, duration)` ([`token_manager.go:121`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/token_manager.go#L121)):

1. Reads 32 bytes from `crypto/rand` as the AES key.
2. Constructs `ID = "<clientName>-<YYYYMMDD-HHMMSS>"`.
3. Sets `ExpiresAt = now + duration`.
4. Adds to the in-memory `map[string]*Token` under `sync.Mutex`.

The generated token is **not** automatically persisted to disk at creation time — that only happens via `saveTokenToFile()` when the token is consumed (see §2.4).  The TUI's "Generate Token" action calls `VPNService.GenerateToken()` which invokes `saveTokenToFile()` immediately after creation as well, writing to `./tokens/<id>.json` with mode 0600.

### 2.3 Token File Format

Each token is stored as a JSON file at `./tokens/<id>.json`:

```json
{
  "id": "alice-20240101-120000",
  "key_hex": "a3f1...64 hex characters...",
  "client_name": "alice",
  "created_at": "2024-01-01T12:00:00Z",
  "expires_at": "2024-01-02T12:00:00Z",
  "used": false
}
```

When consumed:
```json
{
  "used": true,
  "used_at": "2024-01-01T14:30:00Z",
  "used_by": "203.0.113.5:49123"
}
```

The `key_hex` field holds the 32-byte AES key encoded as a 64-character lowercase hex string.  The in-memory `Token.Key` field is tagged `json:"-"` so it is never accidentally serialised — the `saveTokenToFile()` helper uses an anonymous struct that explicitly includes `key_hex` ([`token_manager.go:209`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/token_manager.go#L209)).

### 2.4 One-Time Use Enforcement

`ValidateAndUseToken(tokenID, clientIP)` ([`token_manager.go:161`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/token_manager.go#L161)) acquires a **write lock** for the full duration of validation and mutation.  The sequence is:

1. Acquire `mutex.Lock()`.
2. Look up token by ID — error if not found.
3. Return error if `token.Used == true`.
4. Return error if `time.Now().After(token.ExpiresAt)`.
5. Set `token.Used = true`, `token.UsedAt`, `token.UsedBy`.
6. Call `saveTokenToFile(token)` — flush to disk under the same lock.
7. Release lock, return token.

Because the lock is held from lookup through disk flush, there is no TOCTOU window; a second concurrent request for the same token will block until step 6 completes, then fail at step 3.

### 2.5 Token Crypto — AES-256-GCM

[`token_crypto.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/token_crypto.go) provides two functions:

**`EncryptWithToken(data, tokenKey) → (ciphertext, nonce, error)`**

1. `aes.NewCipher(tokenKey)` — 256-bit AES block cipher.
2. `cipher.NewGCM(block)` — Galois/Counter Mode with authentication tag.
3. `rand.Read(nonce)` — 12-byte random nonce (GCM standard size).
4. `gcm.Seal(nil, nonce, data, nil)` — produces `ciphertext || auth_tag`.

**`DecryptWithToken(ciphertext, nonce, tokenKey) → (plaintext, error)`**

1. Same cipher/GCM setup.
2. `gcm.Open(nil, nonce, ciphertext, nil)` — decrypts and **verifies authentication tag**; returns an error if the tag is invalid, preventing any plaintext from being returned on tampered input.

The authentication tag (16 bytes appended by GCM) ensures both **confidentiality** and **integrity** of the CSR and issued certificate in transit over plain HTTP.  This is important because the cert API server listens on plain HTTP (port 8081) without TLS.

> **Security note:** The cert API endpoint is exposed over unauthenticated plain HTTP.  An active network attacker could observe token IDs (sent in cleartext in the JSON body) and attempt to race a legitimate client to consume a token — however, since the token key is encrypted in the CSR payload, an interceptor who only captures the request cannot decrypt the response.  The one-time-use enforcement (§2.4) and the GCM authentication tag together prevent replay of a previously captured ciphertext.  Administrators should restrict network access to port 8081 to trusted IP ranges or use a reverse proxy with TLS termination for production deployments.

### 2.6 Token Lifecycle Summary

```
generate → [stored in memory + ./tokens/<id>.json]
                 |
           distribute (ID:hex-key out-of-band)
                 |
           client calls POST /api/cert/request
                 |
           ValidateAndUseToken → marked used, flushed to disk
                 |
           [token is exhausted — cannot be reused]
```

Expiry is checked at validation time only; there is no background sweeper removing expired tokens from memory.  The `token/cleanup` API action calls `VPNService.CleanupExpiredTokens()` which iterates the in-memory map and removes entries where `ExpiresAt < now` or `Used == true`, also deleting the corresponding `.json` files.

### 2.7 API Surface

| Control API action | Description |
|-------------------|-------------|
| `token/generate` | `GenerateTokenRequest{ClientName, Duration(hours)}` → `GenerateTokenResponse{TokenID, TokenKey, ExpiresAt, FilePath}` |
| `token/list` | → `TokenListResponse{[]TokenInfo}` (status: `valid` / `used` / `expired`) |
| `token/delete` | `DeleteTokenRequest{Index}` — removes by list position |
| `token/cleanup` | Removes all used/expired tokens from memory and disk |

The TUI exposes all four actions.  The `TokenKey` returned by `token/generate` is the hex-encoded 32-byte key; together with the `TokenID` it forms the `ID:KEY` string the administrator transmits to the client out-of-band.

---

## 3. Control Plane Protocol

### 3.1 Transport

The control plane uses a **Unix domain stream socket** (SOCK_STREAM):

| Platform | Default Path |
|----------|-------------|
| Linux/Unix | `/var/run/vpn_control.sock` (mode 0660) |
| Windows | `%TEMP%\vpn_control.sock` |

Path constants: [`constants_unix.go:7`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/constants_unix.go#L7), [`constants_windows.go:20`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/constants_windows.go#L20).

### 3.2 Message Framing

Both sides use a **newline-delimited JSON** protocol ([`control_server.go:93`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/control_server.go#L93)):

```
Request:   <JSON>\n
Response:  <JSON>\n
```

Each connection carries exactly **one request and one response** — the connection is closed after the response is written.  There is no multiplexing, pipelining, or persistent connection reuse.

**Request structure** ([`api_protocol.go:13`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/api_protocol.go#L13)):
```json
{ "action": "<action-string>", "data": <json-value-or-null> }
```

**Response structure** ([`api_protocol.go:19`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/api_protocol.go#L19)):
```json
{ "success": true|false, "message": "...", "error": "...", "data": <json-value> }
```

### 3.3 Action Catalogue

All action constants are defined in [`api_protocol.go:194`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/api_protocol.go#L194):

| Category | Action | Request Data Type | Response Data Type |
|----------|--------|------------------|--------------------|
| Server | `server/start` | — | message |
| Server | `server/stop` | — | message |
| Server | `server/status` | — | `ServerStatusResponse` |
| Server | `server/clients` | — | `ClientListResponse` |
| Server | `server/kick` | `KickClientRequest{IP}` | message |
| Server | `server/stats` | — | stats struct |
| Client | `client/connect` | — | message |
| Client | `client/disconnect` | — | message |
| Client | `client/status` | — | `VPNClientStatusResponse` |
| Cert | `cert/init-ca` | — | message |
| Cert | `cert/list` | — | `CertListResponse` |
| Cert | `cert/clients` | — | `SignedClientsResponse` |
| Cert | `cert/gen-csr` | `GenerateCSRRequest{ClientName}` | `GenerateCSRResponse` |
| Cert | `cert/request` | `RequestCertRequest` | message |
| Cert | `cert/status` | — | `{exists: bool}` |
| Token | `token/generate` | `GenerateTokenRequest` | `GenerateTokenResponse` |
| Token | `token/list` | — | `TokenListResponse` |
| Token | `token/delete` | `DeleteTokenRequest{Index}` | message |
| Token | `token/cleanup` | — | message |
| Config | `config/get` | — | `ConfigResponse` |
| Config | `config/update` | `UpdateConfigRequest{Field, Value}` | message |
| Config | `config/save` | — | message |
| Config | `config/load` | — | message |
| Config | `config/reset` | — | message |
| Logs | `logs/fetch` | `LogFetchRequest{Since, Limit}` | `LogFetchResponse` |
| System | `ping` | — | `"pong"` |
| System | `shutdown` | — | message |

### 3.4 Concurrency Model

The `ControlServer` ([`control_server.go:14`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/control_server.go#L14)) runs a single `acceptLoop()` goroutine.  Each accepted connection spawns a new goroutine (`handleConnection`).  Because each connection handles only one request, the goroutine terminates immediately after writing the response, so there is no goroutine leakage under normal operation.

The `ControlServer` itself holds a `sync.Mutex` (`mu`) that guards the `running` flag and `listener`; the `done` channel is used for clean termination of `acceptLoop`.

All state mutations that cross the control-plane boundary (e.g., starting the VPN server, modifying config) are serialised by `VPNService.mu` (`sync.RWMutex`): reads use `RLock`, writes use `Lock`.

### 3.5 Local Authorisation

There is **no authentication** on the control socket.  Access is governed entirely by Unix file permissions (mode 0660, group of the running process).  Any process that can open the socket path can issue any action, including `shutdown`.

> **Security note:** On multi-user systems this is a significant privilege boundary.  Any process or user in the same group as the daemon gains full control over the VPN service.  Recommended hardening: run the daemon as a dedicated user and group (e.g., `vpnd`), and ensure only authorised administrators belong to that group.  Windows does not have a direct equivalent; the socket file inherits the DACL of `%TEMP%`, which in practice restricts access to the current user session.  This design is a known architectural simplification appropriate for single-operator deployments.

### 3.6 Shutdown Semantics

The `shutdown` action ([`control_server.go:428`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/control_server.go#L428)) runs asynchronously to avoid a deadlock (the response is sent before the server exits):

```go
go func() {
    s.service.Cleanup()   // stops VPN server/client, removes iptables rules, etc.
    s.Stop()              // closes listener, removes socket file
    os.Exit(0)
}()
return APIResponse{Success: true, Message: "服务正在关闭..."}
```

A `--stop` CLI flag calls `ControlClient.Shutdown()` which sends `shutdown` and prints the response.  The same sequence also runs on `SIGTERM`/`SIGINT` via the signal handler set up in `runServiceDaemon()`.

### 3.7 Client Timeout

`ControlClient` uses a 30-second deadline for both dial and read/write ([`control_client.go:21`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/control_client.go#L21)).  Slow operations (e.g., `cert/init-ca` which generates RSA-4096 keys) may approach or exceed this deadline.

---

## 4. Data Plane Protocol

### 4.1 Overview

The data plane is a **TLS 1.3 stream** carrying an application-layer framing protocol.  IP packets read from the TUN device are wrapped in `Message` frames and written to the TLS connection; the peer reverses the process.

### 4.2 Message Format

Defined in [`protocol_message.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/protocol_message.go):

```
Offset  Length  Field
------  ------  -----
0       1       Type     (uint8, MessageType enum)
1       4       Length   (uint32, big-endian, payload bytes)
5       4       Sequence (uint32, big-endian)
9       4       Checksum (uint32, big-endian; 0 = no checksum)
13      Length  Payload
```

Total header size: **13 bytes**.

**Message types:**

| Value | Name | Description |
|-------|------|-------------|
| 0 | `MessageTypeData` | Encapsulated IP packet |
| 1 | `MessageTypeHeartbeat` | Keepalive ping/pong |
| 2 | `MessageTypeIPAssignment` | Server → client IP config (JSON `ClientConfig`) |
| 3 | `MessageTypeAuth` | Authentication (currently unused post-mTLS) |
| 4 | `MessageTypeControl` | Reserved |

### 4.3 Session Establishment Sequence

```
Client                              Server
  |                                   |
  |==== TLS 1.3 handshake (mTLS) ====>|
  |                                   |
  |<-- MessageTypeIPAssignment --------|  JSON ClientConfig:
  |    {assigned_ip, server_ip,        |  {assigned_ip, server_ip,
  |     dns, routes, mtu,              |   dns, routes, mtu,
  |     route_mode, redirect_*}        |   route_mode, redirect_*}
  |                                   |
  |    [client configures TUN + routes]|
  |                                   |
  |<--> MessageTypeData (IP packets) <-->|
  |<--> MessageTypeHeartbeat          <-->|
```

The `ClientConfig` struct ([`protocol_message.go:67`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/protocol_message.go#L67)) is JSON-encoded and sent as the payload of a `MessageTypeIPAssignment` frame immediately after the TLS handshake.

### 4.4 Sequence Numbers and Checksums

Each message carries a 32-bit sequence number and a 32-bit checksum field.  The checksum value `0` is defined as "no checksum" (pass-through).  The sequence number is included in the frame but the current implementation does not enforce strict ordering or detect replay/loss at the application layer — TLS 1.3 itself provides record-layer ordering and integrity guarantees via AEAD, making duplicate/out-of-order application frames observable only if TLS is somehow bypassed.

**Limitation:** Because the data plane relies entirely on TLS record ordering for sequencing, there is no application-level replay detection window and no packet loss detection.  Dropped TCP segments are retransmitted transparently by the OS TCP stack; the VPN does not implement UDP encapsulation, DTLS, or any datagram-loss recovery.

Additionally, this design exhibits **TCP-over-TCP** behaviour: IP packets from higher-layer TCP connections are encapsulated inside another TCP stream (the TLS connection).  This is a well-known anti-pattern because each layer's retransmission and congestion-control mechanisms interact — when the outer TCP connection experiences loss or delay, inner TCP connections may suffer head-of-line blocking and timeout-induced throughput collapse.  For latency-sensitive workloads or high-loss links, a UDP/DTLS transport (not currently implemented) would be preferable.

### 4.5 Heartbeat

The server sends `MessageTypeHeartbeat` frames at regular intervals (configurable via `keep_alive_timeout_sec`, default 90 s).  If no data or heartbeat is received within the timeout, the session is considered dead and cleaned up.  The cleanup goroutine runs on `session_cleanup_interval_sec` (default 30 s).

### 4.6 Relationship with TLS 1.3

TLS 1.3 provides:
- **Authentication** via mutual X.509 certificate verification (both sides).
- **Confidentiality and integrity** via AEAD (e.g., AES-128-GCM or ChaCha20-Poly1305 depending on cipher negotiation).
- **Perfect forward secrecy** via ephemeral key exchange (X25519 by default in Go's TLS 1.3 implementation).
- **Record ordering** and replay protection at the TLS record layer.

The application-layer `Sequence` and `Checksum` fields are therefore redundant in the context of TLS; they appear to be scaffolding for a possible future UDP/DTLS transport mode.

---

## 5. Platform Differences

### 5.1 TUN Device Creation

| Aspect | Linux/Unix | Windows |
|--------|-----------|---------|
| Library | `github.com/songgao/water` | `golang.zx2c4.com/wireguard/tun` (Wintun) |
| Device creation | `water.New(water.Config{DeviceType: water.TUN, Name: baseName})` | `tun.CreateTUN("tls-vpn", 1500)` |
| Name control | Caller specifies name (e.g., `tls-vpn0`) | Fixed to `"tls-vpn"` |
| Adapter wrapper | `water.Interface` (implements `TUNDevice` directly) | `WintunAdapter` wrapper struct |
| Source | [`tun_device_unix.go:15`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/tun_device_unix.go#L15) | [`tun_device_windows.go:82`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/tun_device_windows.go#L82) |

The `WintunAdapter` ([`tun_device_windows.go:17`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/tun_device_windows.go#L17)) adapts Wintun's batch-oriented `Read(bufs [][]byte, sizes []int, offset int)` / `Write(bufs [][]byte, offset int)` API to the simple `io.ReadWriter` interface expected by the rest of the code.

### 5.2 TUN Device Configuration

| Operation | Linux | Windows |
|-----------|-------|---------|
| Assign IP | `ip addr add <IP> dev <iface>` | `netsh interface ip set address <iface> static <IP> <mask>` |
| Set MTU | `ip link set dev <iface> mtu <mtu>` | `netsh interface ipv4 set subinterface <iface> mtu=<mtu> store=active` |
| Bring up | `ip link set dev <iface> up` | (automatic with Wintun) |
| Source | [`tun_device_unix.go:37`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/tun_device_unix.go#L37) | [`tun_device_windows.go:117`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/tun_device_windows.go#L117) |

Windows also sets interface metric to `1` to give the VPN interface highest routing priority.

### 5.3 Privilege Check

| Platform | Method |
|----------|--------|
| Linux | `id -u` — checks that output starts with `'0'` |
| Windows | `windows.AllocateAndInitializeSid` → `token.IsMember(adminSID)` |
| Source | [`tun_device_unix.go:69`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/tun_device_unix.go#L69), [`tun_device_windows.go:51`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/tun_device_windows.go#L51) |

### 5.4 Route Manager

Both platforms share the same `RouteManager` struct and method signatures but the implementations differ entirely:

| Operation | Linux | Windows |
|-----------|-------|---------|
| Detect default gateway | `ip route show default` | `route print 0.0.0.0 mask 0.0.0.0`, fallback to `netsh`, fallback to `ipconfig` |
| Add route | `ip route add <dst> [via <gw>] [dev <iface>]` | `netsh interface ipv4 add route <CIDR> <iface> <gw> metric=1` or `route add <IP> mask <mask> <gw> metric 1` |
| Delete route | `ip route del <dst>` | `route delete <IP> mask <mask>` |
| Cleanup | Iterates `installedRoutes`, calls `ip route del` | Iterates `installedRoutes`, calls `route delete` |
| Source | [`route_manager.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/route_manager.go) | [`route_manager_windows.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/route_manager_windows.go) |

### 5.5 DNS Handling

| Operation | Linux | Windows |
|-----------|-------|---------|
| Save original DNS | Read `/etc/resolv.conf`, backup to `/etc/resolv.conf.vpn-backup` | `netsh interface ipv4 show dnsservers`, backup to `%TEMP%\vpn_dns_backup.txt` |
| Set DNS | Overwrite `/etc/resolv.conf` | `netsh interface ipv4 set dnsservers <iface> static <primary>` + `add dnsservers` for each additional |
| Restore DNS | Copy backup back to `/etc/resolv.conf`, delete backup | Set from backup, or fallback to `dhcp` if backup missing |
| Disconnect hook | Called by `VPNClient.Disconnect()` | Same |
| Source | [`route_manager.go:169`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/route_manager.go#L169) | [`route_manager_windows.go:268`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/route_manager_windows.go#L268) |

**Note:** On Windows, DNS is set on the VPN interface when `redirect_dns=true` and `vpnIface` is provided; otherwise it falls back to the default physical interface name.  As a last resort the code defaults to the Chinese `"以太网"` / English `"Ethernet"` literal strings.  This fallback is fragile on localised Windows installations with non-standard adapter names; users in such environments should configure `nat_interface` explicitly or ensure the physical adapter name matches one of these strings.  This is a known limitation.

### 5.6 IP Forwarding

| Platform | Method |
|----------|--------|
| Linux | `sysctl -w net.ipv4.ip_forward=1` |
| Windows | Registry: `HKLM\SYSTEM\...\Tcpip\Parameters\IPEnableRouter=1`, restart `RemoteAccess` service |
| Source | [`tun_device_unix.go:84`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/tun_device_unix.go#L84), [`tun_device_windows.go:174`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/tun_device_windows.go#L174) |

### 5.7 NAT (Linux only)

NAT is handled entirely in [`iptables_nat.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/iptables_nat.go) and only compiled for Linux.  Three iptables rules are added:

1. `iptables -t nat -A POSTROUTING -s <vpn_network> -o <iface> -j MASQUERADE`
2. `iptables -A FORWARD -i <tun> -o <iface> -j ACCEPT`
3. `iptables -A FORWARD -i <iface> -o <tun> -m state --state RELATED,ESTABLISHED -j ACCEPT`

All rules are tracked in `server.natRules []NATRule` and deleted on server stop via `VPNServer.CleanupNAT()`.

### 5.8 Socket and Log Paths

| Item | Linux | Windows |
|------|-------|---------|
| Control socket | `/var/run/vpn_control.sock` | `%TEMP%\vpn_control.sock` |
| Log file | `/var/log/tls-vpn.log` | `<exe-dir>\tls-vpn.log` |
| PID file | `/var/run/tlsvpn.pid` | (not used) |
| Source | [`constants_unix.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/constants_unix.go), [`config.go:21`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/config.go#L21) | [`constants_windows.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/constants_windows.go) |

### 5.9 Daemon / Process Launch

| Platform | Mechanism | Source |
|----------|-----------|--------|
| Linux | `os/exec.Command(self, "--service")` with `Setsid=true` (new session, detached from terminal) | [`daemon_unix.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/daemon_unix.go) |
| Windows | `os/exec.Command(self, "--service")` with `CREATE_NEW_PROCESS_GROUP` creation flag | [`daemon_windows.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/daemon_windows.go) |

---

## 6. Configuration Management

### 6.1 In-Memory Representation

`VPNConfig` ([`config.go:78`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/config.go#L78)) is the canonical in-memory configuration type.  It uses Go native types (`time.Duration` etc.) rather than JSON-serialisable primitives.  A parallel `ConfigFile` struct ([`config.go:26`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/config.go#L26)) uses integer seconds for durations and is used exclusively for JSON marshalling/unmarshalling.

### 6.2 Persistence

**Load** (`LoadConfigFromFile`) ([`config.go:197`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/config.go#L197)):
1. Check file exists; return error if not.
2. Read and `json.Unmarshal` into `ConfigFile`.
3. Call `ConfigFile.ToVPNConfig()` to convert to `VPNConfig`.
4. No validation is performed on load — validation happens separately via `ValidateConfig()`.

**Save** (`SaveConfigToFile`) ([`config.go:219`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/config.go#L219)):
1. Convert `VPNConfig` → `ConfigFile` (durations divided by `time.Second`).
2. `json.MarshalIndent` with 2-space indentation.
3. `os.WriteFile(filename, data, 0644)`.

**Default config file path:** `./config.json` (relative to process working directory).

### 6.3 Validation

`VPNConfig.ValidateConfig()` ([`config.go:128`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/config.go#L128)) enforces:

| Field | Constraint |
|-------|-----------|
| `ServerAddress` | Non-empty |
| `ServerPort` | 1–65535 |
| `Network` | Valid CIDR via `net.ParseCIDR` |
| `MTU` | 576–9000 |
| `KeepAliveTimeout` | ≥ 10 s |
| `ReconnectDelay` | ≥ 1 s |
| `MaxConnections` | 1–10000 |
| `SessionTimeout` | ≥ 30 s |
| `SessionCleanupInterval` | ≥ 10 s |
| `ClientIPStart` | 2–253 |
| `ClientIPEnd` | ≥ `ClientIPStart`, ≤ 254 |
| `ServerIP` | Valid CIDR if non-empty |

Validation is called by the TUI before applying config changes and before starting the VPN server.

### 6.4 Hot vs Cold Application

Configuration changes are **cold-applied** — the running VPN server or client is not reconfigured in-place.  Instead, the operator must stop and restart the relevant service for changes to take effect.  The only exception is `config/get` and `config/update` which modify the in-memory `VPNConfig` immediately, but the running server/client continues using parameters captured at startup.

The `config/save` action persists the current in-memory config to `./config.json`.  The `config/load` action reloads from disk.  The `config/reset` action replaces in-memory config with `DefaultConfig` but does not touch the file.

### 6.5 Default Values

| Field | Default |
|-------|---------|
| `server_address` | `"localhost"` |
| `server_port` | `8080` |
| `client_address` | `"10.8.0.2/24"` |
| `network` | `"10.8.0.0/24"` |
| `mtu` | `1500` |
| `keep_alive_timeout_sec` | `90` |
| `reconnect_delay_sec` | `5` |
| `max_connections` | `100` |
| `session_timeout_sec` | `300` |
| `session_cleanup_interval_sec` | `30` |
| `server_ip` | `"10.8.0.1/24"` |
| `client_ip_start` | `2` |
| `client_ip_end` | `254` |
| `dns_servers` | `["8.8.8.8", "8.8.4.4"]` |
| `route_mode` | `"split"` |
| `enable_nat` | `true` |

Source: [`config.go:103`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/config.go#L103).

---

## 7. Observability and Operations

### 7.1 Logging Architecture

The logging stack has two layers ([`service_logger.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/service_logger.go)):

**Layer 1 — `RotatingFileWriter`** ([`service_logger.go:15`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/service_logger.go#L15)):
- Implements `io.Writer`.
- Rotates when file exceeds `maxSizeMB` (default 10 MB).
- Keeps up to `maxBackups` (default 5) numbered backup files (`.1`, `.2`, …).
- Rotation is triggered on write if the next write would exceed the limit; it is not time-based.

**Layer 2 — `ServiceLogBuffer`** ([`service_logger.go:121`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/service_logger.go#L121)):
- An in-memory ring buffer of up to 1000 `LogEntry` values.
- Implements `io.Writer` so it can be passed to `log.SetOutput()`.
- Parses incoming log lines to assign severity (`error` if message contains "错误/失败/Error", `warn` if "警告/Warning", else `info`).
- Writes are forwarded to the `RotatingFileWriter` simultaneously.
- Exposes `GetLogsSince(since uint64, limit int)` for polling by the TUI over the control plane (`logs/fetch`).

In `runServiceDaemon()` ([`main.go:133`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/main.go#L133)):

```go
log.SetOutput(logger)           // all log.Printf calls go to ServiceLogBuffer
log.SetFlags(log.Ldate | log.Ltime)
```

This means all subsystems that use the standard `log` package are captured automatically.

### 7.2 TUI Log Streaming

The TUI polls `logs/fetch` with the last-seen sequence number (`Since`) to receive new log entries since the last poll.  The `LogEntry` structure carries:

```go
type LogEntry struct {
    Seq     uint64  // monotonically increasing, starts at 1
    Time    int64   // Unix ms
    Level   string  // "info" | "warn" | "error"
    Message string
}
```

The `ServiceLogBuffer.GetLogsSince()` method performs a linear scan of the ring buffer for entries with `Seq > since`; for the typical buffer size (1000 entries) this is O(n) but negligible in practice.

### 7.3 Socket Lifecycle

The control socket is created at daemon start and removed at daemon stop:

1. **Start:** `os.Remove(socketPath)` (removes stale socket if it exists), `net.Listen("unix", socketPath)`, `os.Chmod(socketPath, 0660)`.
2. **Stop:** `listener.Close()`, `os.Remove(socketPath)`.

If the daemon crashes without executing `Stop()`, the socket file remains on disk.  The next daemon start removes it via the `os.Remove` in step 1.  The TUI detects a stale socket by attempting `ping` — if the connection fails, it treats the service as not running and starts a new daemon.

### 7.4 PID File

A PID file constant (`DefaultPIDFile = "/var/run/tlsvpn.pid"`) is defined in [`config.go:21`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/config.go#L21) but is **not currently used** by the daemon — the daemon does not write a PID file.  Service presence detection relies entirely on the control socket ping.

### 7.5 Error Handling Patterns

The codebase follows standard Go conventions:

- Functions return `(result, error)` pairs; callers check for non-nil errors.
- Non-fatal errors (e.g., NAT rule addition failure, DNS backup failure) are logged as warnings and do not abort the operation.
- Fatal errors during daemon initialisation use `log.Fatalf` which calls `os.Exit(1)`.
- VPN server/client errors during operation are logged and the relevant subsystem is stopped; the daemon remains running to allow reconnection or restart via the control plane.

**Control plane error propagation:** Handlers in `control_server.go` return `APIResponse{Success: false, Error: err.Error()}` for any failure.  The TUI displays the `Error` field to the user.

### 7.6 Traffic Statistics

`ServerStatusResponse` includes `TotalSent` and `TotalRecv` (uint64 bytes).  Per-client statistics are available via `server/clients` → `ClientInfo{BytesSent, BytesReceived, ConnectedAt, Duration}`.  Statistics are accumulated by the server goroutine for each session; they are **not persisted** across restarts.

---

## Appendix: Key File Index

| File | Purpose |
|------|---------|
| [`main.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/main.go) | Entry point, smart start, daemon mode, status/stop CLI |
| [`vpn_service.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/vpn_service.go) | Business logic orchestrator |
| [`vpn_server.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/vpn_server.go) | TLS server, session management, TUN forwarding loop |
| [`vpn_client.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/vpn_client.go) | TLS client, reconnection loop, route/DNS application |
| [`cert_manager.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/cert_manager.go) | CA/server/client certificate generation and loading |
| [`cert_api_server.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/cert_api_server.go) | HTTP API for token-authenticated certificate issuance |
| [`token_manager.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/token_manager.go) | Token CRUD, one-time-use enforcement, file persistence |
| [`token_crypto.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/token_crypto.go) | AES-256-GCM encrypt/decrypt helpers |
| [`token_file.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/token_file.go) | Token file format / reader (client-side) |
| [`control_server.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/control_server.go) | Unix socket control server, action dispatcher |
| [`control_client.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/control_client.go) | Unix socket control client, typed helper methods |
| [`api_protocol.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/api_protocol.go) | All request/response types and action string constants |
| [`protocol_message.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/protocol_message.go) | Data-plane message framing (13-byte header) |
| [`config.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/config.go) | VPNConfig, defaults, validation, load/save |
| [`service_logger.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/service_logger.go) | Rotating file writer, in-memory log ring buffer |
| [`tun_device_unix.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/tun_device_unix.go) | Linux TUN device creation/config via `ip` commands |
| [`tun_device_windows.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/tun_device_windows.go) | Windows Wintun adapter, `netsh` IP/MTU config |
| [`route_manager.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/route_manager.go) | Linux route and DNS management |
| [`route_manager_windows.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/route_manager_windows.go) | Windows route and DNS management |
| [`iptables_nat.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/iptables_nat.go) | Linux iptables NAT/FORWARD rules |
| [`constants_unix.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/constants_unix.go) | Linux socket/log path constants |
| [`constants_windows.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/constants_windows.go) | Windows socket/log path functions |
| [`daemon_unix.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/daemon_unix.go) | Linux background daemon launch |
| [`daemon_windows.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/daemon_windows.go) | Windows background process launch |
| [`signal_unix.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/signal_unix.go) | SIGTERM/SIGINT handler (Unix) |
| [`signal_windows.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/signal_windows.go) | Console Ctrl-C handler (Windows) |
| [`tui_app.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/tui_app.go) | TUI application scaffolding (`tview`) |
| [`tui_menus.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/tui_menus.go) | Menu tree construction |
| [`tui_handlers.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/tui_handlers.go) | Menu action handlers (IPC calls) |
| [`tui_dialogs.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/tui_dialogs.go) | Input dialogs, confirmation prompts |
| [`tui_theme.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/tui_theme.go) | Colour theme constants |
| [`ip_pool.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/ip_pool.go) | Client IP address pool management |
| [`utils.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/utils.go) | Shared utilities (`formatBytes`, `runCmdCombined`, etc.) |
| [`tun_interface.go`](https://github.com/afoc/TLS-VPN/blob/0b4aeb078ef20f99df212e765cab14c4b6a55145/source/tun_interface.go) | `TUNDevice` interface definition |
