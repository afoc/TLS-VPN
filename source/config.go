package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"
)

// ================ 全局常量 ================

// DefaultCertDir 默认证书目录
const DefaultCertDir = "./certs"

// DefaultConfigFile 默认配置文件路径
const DefaultConfigFile = "./config.json"

// DefaultPIDFile 默认PID文件路径
const DefaultPIDFile = "/var/run/tlsvpn.pid"

// DefaultTokenDir 默认Token目录
const DefaultTokenDir = "./tokens"

// ConfigFile JSON配置文件结构（用于序列化和反序列化）
type ConfigFile struct {
	ServerAddress             string   `json:"server_address"`
	ServerPort                int      `json:"server_port"`
	ClientAddress             string   `json:"client_address"`
	Network                   string   `json:"network"`
	MTU                       int      `json:"mtu"`
	KeepAliveTimeoutSec       int      `json:"keep_alive_timeout_sec"`
	ReconnectDelaySec         int      `json:"reconnect_delay_sec"`
	MaxConnections            int      `json:"max_connections"`
	SessionTimeoutSec         int      `json:"session_timeout_sec"`
	SessionCleanupIntervalSec int      `json:"session_cleanup_interval_sec"`
	ServerIP                  string   `json:"server_ip"`
	ClientIPStart             int      `json:"client_ip_start"`
	ClientIPEnd               int      `json:"client_ip_end"`
	DNSServers                []string `json:"dns_servers"`
	PushRoutes                []string `json:"push_routes"`
	RouteMode                 string   `json:"route_mode"`
	ExcludeRoutes             []string `json:"exclude_routes"`
	RedirectGateway           bool     `json:"redirect_gateway"`
	RedirectDNS               bool     `json:"redirect_dns"`
	EnableNAT                 bool     `json:"enable_nat"`
	NATInterface              string   `json:"nat_interface"`
}

// ToVPNConfig 将ConfigFile转换为VPNConfig
func (cf *ConfigFile) ToVPNConfig() VPNConfig {
	return VPNConfig{
		ServerAddress:          cf.ServerAddress,
		ServerPort:             cf.ServerPort,
		ClientAddress:          cf.ClientAddress,
		Network:                cf.Network,
		MTU:                    cf.MTU,
		KeepAliveTimeout:       time.Duration(cf.KeepAliveTimeoutSec) * time.Second,
		ReconnectDelay:         time.Duration(cf.ReconnectDelaySec) * time.Second,
		MaxConnections:         cf.MaxConnections,
		SessionTimeout:         time.Duration(cf.SessionTimeoutSec) * time.Second,
		SessionCleanupInterval: time.Duration(cf.SessionCleanupIntervalSec) * time.Second,
		ServerIP:               cf.ServerIP,
		ClientIPStart:          cf.ClientIPStart,
		ClientIPEnd:            cf.ClientIPEnd,
		DNSServers:             cf.DNSServers,
		PushRoutes:             cf.PushRoutes,
		RouteMode:              cf.RouteMode,
		ExcludeRoutes:          cf.ExcludeRoutes,
		RedirectGateway:        cf.RedirectGateway,
		RedirectDNS:            cf.RedirectDNS,
		EnableNAT:              cf.EnableNAT,
		NATInterface:           cf.NATInterface,
	}
}

// VPNConfig VPN配置结构
type VPNConfig struct {
	ServerAddress          string
	ServerPort             int
	ClientAddress          string
	Network                string
	MTU                    int
	KeepAliveTimeout       time.Duration
	ReconnectDelay         time.Duration
	MaxConnections         int
	SessionTimeout         time.Duration
	SessionCleanupInterval time.Duration // 新增：会话清理间隔
	ServerIP               string        // 新增：服务器VPN IP (例如 "10.8.0.1/24")
	ClientIPStart          int           // 新增：客户端IP起始 (默认 2)
	ClientIPEnd            int           // 新增：客户端IP结束 (默认 254)
	DNSServers             []string      // 新增：推送给客户端的DNS
	PushRoutes             []string      // 新增：推送给客户端的路由 (CIDR格式)
	RouteMode              string        // 新增：路由模式 "full" 或 "split"
	ExcludeRoutes          []string      // 新增：排除的路由（full模式使用）
	RedirectGateway        bool          // 新增：是否重定向默认网关
	RedirectDNS            bool          // 新增：是否劫持DNS
	EnableNAT              bool          // 新增：服务器端是否启用NAT
	NATInterface           string        // 新增：NAT出口网卡（空字符串=自动检测）
}

// DefaultConfig 默认配置
var DefaultConfig = VPNConfig{
	ServerAddress:          "localhost",
	ServerPort:             8080,
	ClientAddress:          "10.8.0.2/24",
	Network:                "10.8.0.0/24",
	MTU:                    1500,
	KeepAliveTimeout:       90 * time.Second,
	ReconnectDelay:         5 * time.Second,
	MaxConnections:         100,
	SessionTimeout:         5 * time.Minute,
	SessionCleanupInterval: 30 * time.Second,
	ServerIP:               "10.8.0.1/24",
	ClientIPStart:          2,
	ClientIPEnd:            254,
	DNSServers:             []string{"8.8.8.8", "8.8.4.4"},
	PushRoutes:             []string{},
	RouteMode:              "split",
	ExcludeRoutes:          []string{},
	RedirectGateway:        false,
	RedirectDNS:            false,
	EnableNAT:              true,
	NATInterface:           "",
}

// ValidateConfig 验证配置
func (c *VPNConfig) ValidateConfig() error {
	if c.ServerAddress == "" {
		return fmt.Errorf("服务器地址不能为空")
	}
	if c.ServerPort < 1 || c.ServerPort > 65535 {
		return fmt.Errorf("服务器端口必须在1-65535之间")
	}
	if c.Network == "" {
		return fmt.Errorf("VPN网络不能为空")
	}
	if _, _, err := net.ParseCIDR(c.Network); err != nil {
		return fmt.Errorf("VPN网络格式无效: %v", err)
	}
	if c.MTU < 576 || c.MTU > 9000 {
		return fmt.Errorf("MTU必须在576-9000之间")
	}
	if c.KeepAliveTimeout < 10*time.Second {
		return fmt.Errorf("保活超时不能小于10秒")
	}
	if c.ReconnectDelay < 1*time.Second {
		return fmt.Errorf("重连延迟不能小于1秒")
	}
	if c.MaxConnections < 1 || c.MaxConnections > 10000 {
		return fmt.Errorf("最大连接数必须在1-10000之间")
	}
	if c.SessionTimeout < 30*time.Second {
		return fmt.Errorf("会话超时不能小于30秒")
	}
	if c.SessionCleanupInterval < 10*time.Second {
		return fmt.Errorf("会话清理间隔不能小于10秒")
	}
	if c.ClientIPStart < 2 || c.ClientIPStart > 253 {
		return fmt.Errorf("客户端IP起始必须在2-253之间")
	}
	if c.ClientIPEnd < c.ClientIPStart || c.ClientIPEnd > 254 {
		return fmt.Errorf("客户端IP结束必须在起始之后且不超过254")
	}
	// 验证ServerIP（如果提供）
	if c.ServerIP != "" {
		if _, _, err := net.ParseCIDR(c.ServerIP); err != nil {
			return fmt.Errorf("服务器IP格式无效: %v", err)
		}
	}
	return nil
}

// ParseServerIP 解析服务器IP配置
func (c *VPNConfig) ParseServerIP() (net.IP, *net.IPNet, error) {
	if c.ServerIP == "" {
		// 如果未指定，使用Network的第一个IP
		_, network, err := net.ParseCIDR(c.Network)
		if err != nil {
			return nil, nil, fmt.Errorf("无效的网络配置: %v", err)
		}
		ip := network.IP.To4()
		if ip == nil {
			return nil, nil, fmt.Errorf("仅支持IPv4")
		}
		serverIP := net.IPv4(ip[0], ip[1], ip[2], 1)
		return serverIP, network, nil
	}
	ip, ipNet, err := net.ParseCIDR(c.ServerIP)
	if err != nil {
		return nil, nil, fmt.Errorf("无效的服务器IP: %v", err)
	}
	return ip, ipNet, nil
}

// LoadConfigFromFile 从文件加载配置
func LoadConfigFromFile(filename string) (VPNConfig, error) {
	// 检查文件是否存在
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return VPNConfig{}, fmt.Errorf("配置文件不存在: %s", filename)
	}

	// 读取文件
	data, err := os.ReadFile(filename)
	if err != nil {
		return VPNConfig{}, fmt.Errorf("读取配置文件失败: %v", err)
	}

	// 解析JSON
	var configFile ConfigFile
	if err := json.Unmarshal(data, &configFile); err != nil {
		return VPNConfig{}, fmt.Errorf("解析配置文件失败: %v", err)
	}

	return configFile.ToVPNConfig(), nil
}

// SaveConfigToFile 保存配置到文件（创建示例配置）
func SaveConfigToFile(filename string, config VPNConfig) error {
	configFile := ConfigFile{
		ServerAddress:             config.ServerAddress,
		ServerPort:                config.ServerPort,
		ClientAddress:             config.ClientAddress,
		Network:                   config.Network,
		MTU:                       config.MTU,
		KeepAliveTimeoutSec:       int(config.KeepAliveTimeout / time.Second),
		ReconnectDelaySec:         int(config.ReconnectDelay / time.Second),
		MaxConnections:            config.MaxConnections,
		SessionTimeoutSec:         int(config.SessionTimeout / time.Second),
		SessionCleanupIntervalSec: int(config.SessionCleanupInterval / time.Second),
		ServerIP:                  config.ServerIP,
		ClientIPStart:             config.ClientIPStart,
		ClientIPEnd:               config.ClientIPEnd,
		DNSServers:                config.DNSServers,
		PushRoutes:                config.PushRoutes,
		RouteMode:                 config.RouteMode,
		ExcludeRoutes:             config.ExcludeRoutes,
		RedirectGateway:           config.RedirectGateway,
		RedirectDNS:               config.RedirectDNS,
		EnableNAT:                 config.EnableNAT,
		NATInterface:              config.NATInterface,
	}

	data, err := json.MarshalIndent(configFile, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化配置失败: %v", err)
	}

	return os.WriteFile(filename, data, 0644)
}

// autoSaveConfig 已废弃，配置保存通过 VPNService.SaveConfig() 处理
