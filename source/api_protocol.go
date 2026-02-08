package main

import (
	"encoding/json"
	"time"
)

// ControlSocketPath 在 constants_unix.go 和 constants_windows.go 中定义

// ================ API 请求/响应协议 ================

// APIRequest 通用请求结构
type APIRequest struct {
	Action string          `json:"action"` // 操作类型
	Data   json.RawMessage `json:"data"`   // 请求数据（可选）
}

// APIResponse 通用响应结构
type APIResponse struct {
	Success bool            `json:"success"`
	Message string          `json:"message,omitempty"`
	Error   string          `json:"error,omitempty"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// ================ 具体请求/响应类型 ================

// --- 服务端相关 ---

// ServerStatusResponse 服务端状态响应
type ServerStatusResponse struct {
	Running     bool   `json:"running"`
	Port        int    `json:"port,omitempty"`
	TUNDevice   string `json:"tun_device,omitempty"`
	Network     string `json:"network,omitempty"`
	ClientCount int    `json:"client_count"`
	TotalSent   uint64 `json:"total_sent"`
	TotalRecv   uint64 `json:"total_recv"`
}

// ClientInfo 客户端信息
type ClientInfo struct {
	IP            string    `json:"ip"`
	BytesSent     uint64    `json:"bytes_sent"`
	BytesReceived uint64    `json:"bytes_received"`
	ConnectedAt   time.Time `json:"connected_at"`
	Duration      string    `json:"duration"`
}

// ClientListResponse 客户端列表响应
type ClientListResponse struct {
	Clients []ClientInfo `json:"clients"`
}

// KickClientRequest 踢出客户端请求
type KickClientRequest struct {
	IP string `json:"ip"`
}

// --- 客户端相关 ---

// VPNClientStatusResponse VPN客户端状态响应
type VPNClientStatusResponse struct {
	Connected     bool   `json:"connected"`
	ServerAddress string `json:"server_address,omitempty"`
	ServerPort    int    `json:"server_port,omitempty"`
	AssignedIP    string `json:"assigned_ip,omitempty"`
	TUNDevice     string `json:"tun_device,omitempty"`
}

// --- 证书相关 ---

// CertListResponse 证书列表响应
type CertListResponse struct {
	CertDir string     `json:"cert_dir"`
	Files   []CertFile `json:"files"`
}

// CertFile 证书文件信息
type CertFile struct {
	Name     string    `json:"name"`
	Exists   bool      `json:"exists"`
	Size     int64     `json:"size,omitempty"`
	Modified time.Time `json:"modified,omitempty"`
}

// SignedClientsResponse 已签发客户端响应
type SignedClientsResponse struct {
	Clients []SignedClient `json:"clients"`
}

// SignedClient 已签发的客户端证书
type SignedClient struct {
	Name     string    `json:"name"`
	Modified time.Time `json:"modified"`
}

// --- Token 相关 ---

// GenerateTokenRequest 生成 Token 请求
type GenerateTokenRequest struct {
	ClientName string `json:"client_name"`
	Duration   int    `json:"duration"` // 有效期（小时）
}

// GenerateTokenResponse 生成 Token 响应
type GenerateTokenResponse struct {
	TokenID    string    `json:"token_id"`
	TokenKey   string    `json:"token_key"`
	ClientName string    `json:"client_name"`
	ExpiresAt  time.Time `json:"expires_at"`
	FilePath   string    `json:"file_path"`
}

// TokenListResponse Token 列表响应
type TokenListResponse struct {
	Tokens []TokenInfo `json:"tokens"`
}

// TokenInfo Token 信息
type TokenInfo struct {
	ID         string    `json:"id"`
	ClientName string    `json:"client_name"`
	Status     string    `json:"status"` // "valid", "used", "expired"
	ExpiresAt  time.Time `json:"expires_at"`
}

// DeleteTokenRequest 删除 Token 请求
type DeleteTokenRequest struct {
	Index int `json:"index"` // Token 索引（从1开始）
}

// --- 配置相关 ---

// ConfigResponse 配置响应
type ConfigResponse struct {
	Config VPNConfig `json:"config"`
}

// UpdateConfigRequest 更新配置请求
type UpdateConfigRequest struct {
	Field string      `json:"field"` // 字段名
	Value interface{} `json:"value"` // 新值
}

// --- CSR/证书申请相关 ---

// GenerateCSRRequest 生成 CSR 请求
type GenerateCSRRequest struct {
	ClientName string `json:"client_name"`
}

// GenerateCSRResponse 生成 CSR 响应
type GenerateCSRResponse struct {
	CSRFile string `json:"csr_file"`
	KeyFile string `json:"key_file"`
	CN      string `json:"cn"`
}

// RequestCertRequest 申请证书请求
type RequestCertRequest struct {
	CSRFile       string `json:"csr_file"`
	TokenFile     string `json:"token_file,omitempty"`
	TokenID       string `json:"token_id,omitempty"`
	TokenKey      string `json:"token_key,omitempty"`
	ServerAddress string `json:"server_address"`
	ServerPort    int    `json:"server_port"`
}

// ================ 日志相关 ================

// LogEntry 日志条目
type LogEntry struct {
	Seq     uint64 `json:"seq"`     // 序号
	Time    int64  `json:"time"`    // Unix 时间戳（毫秒）
	Level   string `json:"level"`   // 日志级别: info, warn, error
	Message string `json:"message"` // 日志内容
}

// LogFetchRequest 获取日志请求
type LogFetchRequest struct {
	Since uint64 `json:"since"` // 从哪个序号之后开始获取
	Limit int    `json:"limit"` // 最多获取多少条（0=不限制）
}

// LogFetchResponse 获取日志响应
type LogFetchResponse struct {
	Logs    []LogEntry `json:"logs"`     // 日志列表
	LastSeq uint64     `json:"last_seq"` // 最后一条日志的序号
}

// ================ API Action 常量 ================

const (
	// 服务端
	ActionServerStart   = "server/start"
	ActionServerStop    = "server/stop"
	ActionServerStatus  = "server/status"
	ActionServerClients = "server/clients"
	ActionServerKick    = "server/kick"
	ActionServerStats   = "server/stats"

	// 客户端
	ActionClientConnect    = "client/connect"
	ActionClientDisconnect = "client/disconnect"
	ActionClientStatus     = "client/status"

	// 证书
	ActionCertInitCA  = "cert/init-ca"
	ActionCertList    = "cert/list"
	ActionCertClients = "cert/clients"
	ActionCertGenCSR  = "cert/gen-csr"
	ActionCertRequest = "cert/request"
	ActionCertStatus  = "cert/status"

	// Token
	ActionTokenGenerate = "token/generate"
	ActionTokenList     = "token/list"
	ActionTokenDelete   = "token/delete"
	ActionTokenCleanup  = "token/cleanup"

	// 配置
	ActionConfigGet    = "config/get"
	ActionConfigUpdate = "config/update"
	ActionConfigSave   = "config/save"
	ActionConfigLoad   = "config/load"
	ActionConfigReset  = "config/reset"

	// 日志
	ActionLogFetch = "logs/fetch"

	// 系统
	ActionPing     = "ping"
	ActionShutdown = "shutdown"
)
