package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// VPNService VPN 服务层，封装所有业务逻辑
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

// NewVPNService 创建 VPN 服务实例
func NewVPNService() *VPNService {
	s := &VPNService{
		config:     DefaultConfig,
		configFile: DefaultConfigFile,
		certDir:    DefaultCertDir,
		tokenDir:   DefaultTokenDir,
	}
	// 尝试加载配置
	if cfg, err := LoadConfigFromFile(s.configFile); err == nil {
		s.config = cfg
	}
	return s
}

// ================ 服务端操作 ================

// StartServer 启动 VPN 服务端
func (s *VPNService) StartServer() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.server != nil && s.server.IsRunning() {
		return fmt.Errorf("服务端已在运行")
	}

	// 获取证书管理器
	certManager, err := s.getOrInitCertManager(true)
	if err != nil {
		return fmt.Errorf("初始化证书失败: %v", err)
	}

	// 创建服务器
	serverAddr := fmt.Sprintf(":%d", s.config.ServerPort)
	server, err := NewVPNServer(serverAddr, certManager, s.config)
	if err != nil {
		return fmt.Errorf("创建服务器失败: %v", err)
	}

	// 初始化 TUN 设备
	if err := server.InitializeTUN(); err != nil {
		return fmt.Errorf("初始化TUN设备失败: %v", err)
	}

	// 配置 NAT
	if s.config.EnableNAT {
		if err := setupServerNAT(server, s.config); err != nil {
			// NAT 失败不阻止启动，只记录警告
			fmt.Printf("警告: 配置NAT失败: %v\n", err)
		}
	}

	// 启动证书 API 服务器
	s.startCertAPIServer(certManager)

	s.server = server
	go server.Start(context.Background())

	return nil
}

// StopServer 停止 VPN 服务端
func (s *VPNService) StopServer() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.server == nil || !s.server.IsRunning() {
		return fmt.Errorf("服务端未运行")
	}

	s.server.Stop()
	s.server = nil

	if s.apiServer != nil {
		s.apiServer.Stop()
		s.apiServer = nil
	}

	return nil
}

// GetServerStatus 获取服务端状态
func (s *VPNService) GetServerStatus() ServerStatusResponse {
	s.mu.RLock()
	defer s.mu.RUnlock()

	resp := ServerStatusResponse{
		Running: s.server != nil && s.server.IsRunning(),
	}

	if resp.Running {
		resp.Port = s.config.ServerPort
		resp.TUNDevice = s.server.GetTUNDeviceName()
		resp.Network = s.config.Network
		resp.ClientCount = s.server.GetSessionCount()
		resp.TotalSent, resp.TotalRecv = s.server.GetTotalStats()
	}

	return resp
}

// GetOnlineClients 获取在线客户端列表
func (s *VPNService) GetOnlineClients() []ClientInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.server == nil || !s.server.IsRunning() {
		return nil
	}

	sessions := s.server.GetAllSessions()
	clients := make([]ClientInfo, 0, len(sessions))
	for _, sess := range sessions {
		clients = append(clients, ClientInfo{
			IP:            sess.IP,
			BytesSent:     sess.BytesSent,
			BytesReceived: sess.BytesReceived,
			ConnectedAt:   sess.ConnectedAt,
			Duration:      time.Since(sess.ConnectedAt).Truncate(time.Second).String(),
		})
	}
	return clients
}

// KickClient 踢出指定客户端
func (s *VPNService) KickClient(ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.server == nil || !s.server.IsRunning() {
		return fmt.Errorf("服务端未运行")
	}

	if !s.server.KickByIP(ip) {
		return fmt.Errorf("未找到客户端: %s", ip)
	}
	return nil
}

// ================ 客户端操作 ================

// ConnectClient 连接 VPN
func (s *VPNService) ConnectClient() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.client != nil && s.client.IsRunning() {
		return fmt.Errorf("客户端已在运行")
	}

	// 获取证书管理器（客户端模式）
	certManager, err := LoadCertificateManagerForClient(s.certDir)
	if err != nil {
		return fmt.Errorf("加载证书失败: %v (请先申请证书)", err)
	}

	client := NewVPNClient(certManager, s.config)
	if err := client.InitializeTUN(); err != nil {
		return fmt.Errorf("初始化TUN设备失败: %v", err)
	}

	s.client = client
	go client.Run(context.Background())

	return nil
}

// DisconnectClient 断开 VPN
func (s *VPNService) DisconnectClient() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.client == nil || !s.client.IsRunning() {
		return fmt.Errorf("客户端未连接")
	}

	s.client.Close()
	s.client = nil
	return nil
}

// GetClientStatus 获取客户端状态
func (s *VPNService) GetClientStatus() VPNClientStatusResponse {
	s.mu.RLock()
	defer s.mu.RUnlock()

	resp := VPNClientStatusResponse{
		Connected:     s.client != nil && s.client.IsRunning(),
		ServerAddress: s.config.ServerAddress,
		ServerPort:    s.config.ServerPort,
	}

	if resp.Connected && s.client != nil {
		if s.client.assignedIP != nil {
			resp.AssignedIP = s.client.assignedIP.String()
		}
		if s.client.tunDevice != nil {
			resp.TUNDevice = s.client.tunDevice.Name()
		}
	}

	return resp
}

// ================ 证书操作 ================

// InitCA 初始化 CA
func (s *VPNService) InitCA() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cm, err := NewCertificateManager()
	if err != nil {
		return err
	}
	s.certManager = cm
	return nil
}

// CertificatesExistCheck 检查证书是否存在
func (s *VPNService) CertificatesExistCheck() bool {
	return CertificatesExist(s.certDir)
}

// GetCertList 获取证书列表
func (s *VPNService) GetCertList() CertListResponse {
	certFiles := []string{"ca.pem", "ca-key.pem", "server.pem", "server-key.pem", "client.pem", "client-key.pem"}
	resp := CertListResponse{
		CertDir: s.certDir,
		Files:   make([]CertFile, 0, len(certFiles)),
	}

	for _, file := range certFiles {
		cf := CertFile{Name: file, Exists: false}
		path := s.certDir + "/" + file
		if info, err := os.Stat(path); err == nil {
			cf.Exists = true
			cf.Size = info.Size()
			cf.Modified = info.ModTime()
		}
		resp.Files = append(resp.Files, cf)
	}
	return resp
}

// GetSignedClients 获取已签发的客户端证书
func (s *VPNService) GetSignedClients() []SignedClient {
	files, err := os.ReadDir(s.certDir)
	if err != nil {
		return nil
	}

	var clients []SignedClient
	for _, f := range files {
		name := f.Name()
		if strings.HasSuffix(name, ".pem") && !strings.HasSuffix(name, "-key.pem") {
			if name != "ca.pem" && name != "server.pem" && name != "client.pem" {
				info, _ := f.Info()
				clients = append(clients, SignedClient{
					Name:     name,
					Modified: info.ModTime(),
				})
			}
		}
	}
	return clients
}

// GenerateCSR 生成 CSR
func (s *VPNService) GenerateCSR(clientName string) (*GenerateCSRResponse, error) {
	if clientName == "" {
		return nil, fmt.Errorf("客户端名称不能为空")
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("生成私钥失败: %v", err)
	}

	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("vpn-client-%s", clientName),
			Organization: []string{"SecureVPN Organization"},
			Country:      []string{"CN"},
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privateKey)
	if err != nil {
		return nil, fmt.Errorf("生成CSR失败: %v", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	keyFile := fmt.Sprintf("%s-key.pem", clientName)
	csrFile := fmt.Sprintf("%s.csr", clientName)

	if err := os.WriteFile(keyFile, privateKeyPEM, 0600); err != nil {
		return nil, fmt.Errorf("保存私钥失败: %v", err)
	}
	if err := os.WriteFile(csrFile, csrPEM, 0644); err != nil {
		return nil, fmt.Errorf("保存CSR失败: %v", err)
	}

	return &GenerateCSRResponse{
		CSRFile: csrFile,
		KeyFile: keyFile,
		CN:      csrTemplate.Subject.CommonName,
	}, nil
}

// RequestCert 申请证书
func (s *VPNService) RequestCert(req RequestCertRequest) error {
	var tokenID, tokenKey string

	// 从文件读取 Token
	if req.TokenFile != "" {
		id, key, err := readTokenFromFile(req.TokenFile)
		if err != nil {
			return fmt.Errorf("读取Token失败: %v", err)
		}
		tokenID = id
		tokenKey = key
	} else {
		tokenID = req.TokenID
		tokenKey = req.TokenKey
	}

	if tokenID == "" || tokenKey == "" {
		return fmt.Errorf("缺少Token信息")
	}

	// 验证 CSR 文件
	csrPEM, err := os.ReadFile(req.CSRFile)
	if err != nil {
		return fmt.Errorf("读取CSR文件失败: %v", err)
	}

	// 解码 Token 密钥
	key, err := hex.DecodeString(tokenKey)
	if err != nil || len(key) != 32 {
		return fmt.Errorf("Token Key格式错误")
	}

	// 加密 CSR
	encryptedCSR, nonce, err := EncryptWithToken(csrPEM, key)
	if err != nil {
		return fmt.Errorf("加密CSR失败: %v", err)
	}

	// 发送请求
	certReq := EncryptedCertRequest{
		TokenID:      tokenID,
		EncryptedCSR: encryptedCSR,
		Nonce:        nonce,
	}
	reqData, _ := json.Marshal(certReq)

	url := fmt.Sprintf("http://%s:%d/api/cert/request", req.ServerAddress, req.ServerPort)
	resp, err := http.Post(url, "application/json", strings.NewReader(string(reqData)))
	if err != nil {
		return fmt.Errorf("发送请求失败: %v", err)
	}
	defer resp.Body.Close()

	var certResp EncryptedCertResponse
	if err := json.NewDecoder(resp.Body).Decode(&certResp); err != nil {
		return fmt.Errorf("解析响应失败: %v", err)
	}
	if !certResp.Success {
		return fmt.Errorf("服务器返回错误: %s", certResp.Error)
	}

	// 解密证书
	certPEM, err := DecryptWithToken(certResp.EncryptedCert, certResp.Nonce, key)
	if err != nil {
		return fmt.Errorf("解密证书失败: %v", err)
	}

	// 解密 CA 证书
	var caCertPEM []byte
	if len(certResp.EncryptedCA) > 0 && len(certResp.CANonce) > 0 {
		caCertPEM, err = DecryptWithToken(certResp.EncryptedCA, certResp.CANonce, key)
		if err != nil {
			return fmt.Errorf("解密CA证书失败: %v", err)
		}
	}

	// 保存证书
	os.MkdirAll(s.certDir, 0700)

	if len(caCertPEM) > 0 {
		if err := os.WriteFile(s.certDir+"/ca.pem", caCertPEM, 0644); err != nil {
			return fmt.Errorf("保存CA证书失败: %v", err)
		}
	}

	if err := os.WriteFile(s.certDir+"/client.pem", certPEM, 0644); err != nil {
		return fmt.Errorf("保存客户端证书失败: %v", err)
	}

	// 复制私钥
	keyFile := strings.TrimSuffix(req.CSRFile, ".csr") + "-key.pem"
	if keyPEM, err := os.ReadFile(keyFile); err == nil {
		if err := os.WriteFile(s.certDir+"/client-key.pem", keyPEM, 0600); err != nil {
			return fmt.Errorf("保存客户端私钥失败: %v", err)
		}
	}

	return nil
}

// ================ Token 操作 ================

// GenerateToken 生成 Token
func (s *VPNService) GenerateToken(clientName string, duration int) (*GenerateTokenResponse, error) {
	if clientName == "" {
		return nil, fmt.Errorf("客户端名称不能为空")
	}
	if duration <= 0 {
		duration = 24
	}

	s.mu.RLock()
	var tm *TokenManager
	if s.apiServer != nil {
		tm = s.apiServer.GetTokenManager()
	}
	s.mu.RUnlock()

	if tm == nil {
		tm = NewTokenManager()
	}

	token, err := tm.GenerateToken(clientName, time.Duration(duration)*time.Hour)
	if err != nil {
		return nil, err
	}

	keyHex := hex.EncodeToString(token.Key)

	// 保存 Token
	os.MkdirAll(s.tokenDir, 0700)
	tokenFile := fmt.Sprintf("%s/%s.json", s.tokenDir, token.ID)

	tokenData := struct {
		ID         string    `json:"id"`
		KeyHex     string    `json:"key_hex"`
		ClientName string    `json:"client_name"`
		CreatedAt  time.Time `json:"created_at"`
		ExpiresAt  time.Time `json:"expires_at"`
		Used       bool      `json:"used"`
	}{
		ID:         token.ID,
		KeyHex:     keyHex,
		ClientName: token.ClientName,
		CreatedAt:  token.CreatedAt,
		ExpiresAt:  token.ExpiresAt,
		Used:       token.Used,
	}

	jsonData, _ := json.MarshalIndent(tokenData, "", "  ")
	if err := os.WriteFile(tokenFile, jsonData, 0600); err != nil {
		return nil, fmt.Errorf("保存Token失败: %v", err)
	}

	return &GenerateTokenResponse{
		TokenID:    token.ID,
		TokenKey:   keyHex,
		ClientName: token.ClientName,
		ExpiresAt:  token.ExpiresAt,
		FilePath:   tokenFile,
	}, nil
}

// GetTokenList 获取 Token 列表
func (s *VPNService) GetTokenList() []TokenInfo {
	files, err := os.ReadDir(s.tokenDir)
	if err != nil {
		return nil
	}

	var tokens []TokenInfo
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(s.tokenDir + "/" + f.Name())
		if err != nil {
			continue
		}
		var token Token
		if json.Unmarshal(data, &token) != nil {
			continue
		}

		status := "valid"
		if token.Used {
			status = "used"
		} else if time.Now().After(token.ExpiresAt) {
			status = "expired"
		}

		tokens = append(tokens, TokenInfo{
			ID:         token.ID,
			ClientName: token.ClientName,
			Status:     status,
			ExpiresAt:  token.ExpiresAt,
		})
	}
	return tokens
}

// DeleteToken 删除 Token
func (s *VPNService) DeleteToken(index int) error {
	files, _ := os.ReadDir(s.tokenDir)
	var tokenFiles []string
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".json") {
			tokenFiles = append(tokenFiles, f.Name())
		}
	}

	if index < 1 || index > len(tokenFiles) {
		return fmt.Errorf("无效的序号")
	}

	path := s.tokenDir + "/" + tokenFiles[index-1]
	return os.Remove(path)
}

// CleanupExpiredTokens 清理过期 Token
func (s *VPNService) CleanupExpiredTokens() int {
	files, _ := os.ReadDir(s.tokenDir)
	cleaned := 0

	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".json") {
			continue
		}
		path := s.tokenDir + "/" + f.Name()
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var token Token
		if json.Unmarshal(data, &token) != nil {
			continue
		}
		if token.Used || time.Now().After(token.ExpiresAt) {
			if os.Remove(path) == nil {
				cleaned++
			}
		}
	}
	return cleaned
}

// ================ 配置操作 ================

// GetConfig 获取当前配置
func (s *VPNService) GetConfig() VPNConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config
}

// UpdateConfig 更新配置字段
func (s *VPNService) UpdateConfig(field string, value interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch field {
	case "server_port":
		if v, ok := value.(float64); ok {
			port := int(v)
			if port > 0 && port < 65536 {
				s.config.ServerPort = port
			} else {
				return fmt.Errorf("无效的端口号")
			}
		}
	case "server_address":
		if v, ok := value.(string); ok {
			s.config.ServerAddress = v
		}
	case "network":
		if v, ok := value.(string); ok {
			if _, _, err := net.ParseCIDR(v); err != nil {
				return fmt.Errorf("无效的网段格式")
			}
			s.config.Network = v
		}
	case "mtu":
		if v, ok := value.(float64); ok {
			mtu := int(v)
			if mtu >= 576 && mtu <= 9000 {
				s.config.MTU = mtu
			} else {
				return fmt.Errorf("MTU必须在576-9000之间")
			}
		}
	case "route_mode":
		if v, ok := value.(string); ok {
			s.config.RouteMode = v
		}
	case "enable_nat":
		if v, ok := value.(bool); ok {
			s.config.EnableNAT = v
		}
	case "redirect_gateway":
		if v, ok := value.(bool); ok {
			s.config.RedirectGateway = v
		}
	case "nat_interface":
		if v, ok := value.(string); ok {
			s.config.NATInterface = v
		}
	case "max_connections":
		if v, ok := value.(float64); ok {
			max := int(v)
			if max > 0 && max <= 10000 {
				s.config.MaxConnections = max
			} else {
				return fmt.Errorf("无效的连接数")
			}
		}
	case "push_routes":
		if v, ok := value.([]interface{}); ok {
			routes := make([]string, 0, len(v))
			for _, r := range v {
				if rs, ok := r.(string); ok {
					// 验证路由格式
					if rs != "" {
						if _, _, err := net.ParseCIDR(rs); err != nil {
							return fmt.Errorf("无效的路由格式: %s", rs)
						}
						routes = append(routes, rs)
					}
				}
			}
			s.config.PushRoutes = routes
		}
	case "redirect_dns":
		if v, ok := value.(bool); ok {
			s.config.RedirectDNS = v
		}
	case "dns_servers":
		if v, ok := value.([]interface{}); ok {
			servers := make([]string, 0, len(v))
			for _, d := range v {
				if ds, ok := d.(string); ok {
					// 验证IP格式
					if ds != "" {
						if net.ParseIP(ds) == nil {
							return fmt.Errorf("无效的DNS服务器地址: %s", ds)
						}
						servers = append(servers, ds)
					}
				}
			}
			if len(servers) == 0 {
				return fmt.Errorf("至少需要一个DNS服务器")
			}
			s.config.DNSServers = servers
		}
	default:
		return fmt.Errorf("未知的配置字段: %s", field)
	}

	// 自动保存
	s.saveConfigNoLock()
	return nil
}

// SaveConfig 保存配置
func (s *VPNService) SaveConfig() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveConfigNoLock()
}

func (s *VPNService) saveConfigNoLock() error {
	return SaveConfigToFile(s.configFile, s.config)
}

// LoadConfig 加载配置
func (s *VPNService) LoadConfig() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cfg, err := LoadConfigFromFile(s.configFile)
	if err != nil {
		return err
	}
	s.config = cfg
	return nil
}

// ResetConfig 重置配置
func (s *VPNService) ResetConfig() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config = DefaultConfig
	s.saveConfigNoLock()
}

// ================ 内部方法 ================

func (s *VPNService) getOrInitCertManager(serverMode bool) (*CertificateManager, error) {
	if s.certManager != nil {
		return s.certManager, nil
	}

	var cm *CertificateManager
	var err error

	if serverMode {
		cm, err = NewCertificateManager()
	} else {
		cm, err = LoadCertificateManagerForClient(s.certDir)
	}

	if err != nil {
		return nil, err
	}
	s.certManager = cm
	return cm, nil
}

func (s *VPNService) startCertAPIServer(certManager *CertificateManager) {
	caCertPEM, _ := os.ReadFile(s.certDir + "/ca.pem")
	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		return
	}
	caCert, _ := x509.ParseCertificate(block.Bytes)
	caKey, _ := LoadCAKey(s.certDir)
	if caCert != nil && caKey != nil {
		s.apiServer = NewCertAPIServer(8081, certManager, caCert, caKey)
		go s.apiServer.Start()
	}
}

// Cleanup 清理资源
func (s *VPNService) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.server != nil {
		s.server.Stop()
		s.server = nil
	}
	if s.client != nil {
		s.client.Close()
		s.client = nil
	}
	if s.apiServer != nil {
		s.apiServer.Stop()
		s.apiServer = nil
	}
}

// IsServerRunning 检查服务端是否运行
func (s *VPNService) IsServerRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.server != nil && s.server.IsRunning()
}

// IsClientRunning 检查客户端是否运行
func (s *VPNService) IsClientRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.client != nil && s.client.IsRunning()
}
