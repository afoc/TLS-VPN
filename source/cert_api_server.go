package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"
)

// CertAPIServer 证书API服务器
type CertAPIServer struct {
	tokenManager *TokenManager
	certManager  *CertificateManager
	caCert       *x509.Certificate
	caKey        *rsa.PrivateKey
	port         int
	server       *http.Server
}

// GetTokenManager 获取Token管理器（用于外部添加Token）
func (api *CertAPIServer) GetTokenManager() *TokenManager {
	return api.tokenManager
}

// ReloadTokens 重新加载Token（从文件系统）
func (api *CertAPIServer) ReloadTokens() error {
	if err := api.tokenManager.LoadTokensFromDir(DefaultTokenDir); err != nil {
		return fmt.Errorf("重新加载Token失败: %v", err)
	}
	log.Printf("[API] Token已重新加载，当前共 %d 个", api.tokenManager.TokenCount())
	return nil
}

// NewCertAPIServer 创建证书API服务器
func NewCertAPIServer(port int, certManager *CertificateManager, caCert *x509.Certificate, caKey *rsa.PrivateKey) *CertAPIServer {
	return &CertAPIServer{
		tokenManager: NewTokenManagerWithLoad(DefaultTokenDir), // 加载已有Token
		certManager:  certManager,
		caCert:       caCert,
		caKey:        caKey,
		port:         port,
	}
}

// Start 启动API服务器
func (api *CertAPIServer) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/cert/request", api.handleCertRequest)
	mux.HandleFunc("/api/health", api.handleHealth)

	api.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", api.port),
		Handler: mux,
	}

	log.Printf("[API] 证书API服务器启动: http://0.0.0.0:%d", api.port)
	log.Printf("[API] 已加载Token: %d 个", api.tokenManager.TokenCount())
	log.Printf("[API] 端点:")
	log.Printf("[API]   - POST /api/cert/request - 提交加密的CSR")
	log.Printf("[API]   - GET  /api/health - 健康检查")

	return api.server.ListenAndServe()
}

// Stop 停止API服务器
func (api *CertAPIServer) Stop() error {
	if api.server != nil {
		log.Printf("[API] 证书API服务器正在停止...")
		err := api.server.Close()
		if err == nil {
			log.Printf("[API] 证书API服务器已停止")
		}
		return err
	}
	return nil
}

// handleHealth 健康检查
func (api *CertAPIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"time":    time.Now().Format(time.RFC3339),
		"service": "VPN Certificate API",
	})
}

// handleCertRequest 处理证书请求
func (api *CertAPIServer) handleCertRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只支持POST请求", http.StatusMethodNotAllowed)
		return
	}

	// 获取客户端IP
	clientIP := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		clientIP = forwarded
	}

	// 解析请求
	var req EncryptedCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.sendError(w, "解析请求失败: "+err.Error(), http.StatusBadRequest)
		return
	}

	log.Printf("[API] 收到证书请求 - Token: %s, 来自: %s", req.TokenID, clientIP)

	// 验证并使用Token
	token, err := api.tokenManager.ValidateAndUseToken(req.TokenID, clientIP)
	if err != nil {
		log.Printf("[API] Token验证失败: %v", err)
		api.sendError(w, "Token验证失败: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// 使用Token密钥解密CSR
	csrPEM, err := DecryptWithToken(req.EncryptedCSR, req.Nonce, token.Key)
	if err != nil {
		log.Printf("[API] 解密CSR失败: %v", err)
		api.sendError(w, "解密CSR失败: "+err.Error(), http.StatusBadRequest)
		return
	}

	// 解析CSR
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		api.sendError(w, "CSR格式错误", http.StatusBadRequest)
		return
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		api.sendError(w, "解析CSR失败: "+err.Error(), http.StatusBadRequest)
		return
	}

	// 验证CSR签名
	if err := csr.CheckSignature(); err != nil {
		api.sendError(w, "CSR签名无效: "+err.Error(), http.StatusBadRequest)
		return
	}

	log.Printf("[API] CSR验证通过 - CN: %s, 算法: %s", csr.Subject.CommonName, csr.SignatureAlgorithm)

	// 签发证书
	certPEM, err := api.signCertificate(csr)
	if err != nil {
		log.Printf("[API] 签发证书失败: %v", err)
		api.sendError(w, "签发证书失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 使用Token密钥加密证书
	encryptedCert, nonce, err := EncryptWithToken(certPEM, token.Key)
	if err != nil {
		api.sendError(w, "加密证书失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 读取CA证书并加密
	caCertPEM, err := os.ReadFile(DefaultCertDir + "/ca.pem")
	if err != nil {
		log.Printf("[API] 读取CA证书失败: %v", err)
		api.sendError(w, "读取CA证书失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	encryptedCA, caNonce, err := EncryptWithToken(caCertPEM, token.Key)
	if err != nil {
		api.sendError(w, "加密CA证书失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("[API] 证书已签发 - 客户端: %s, Token: %s (含CA证书)", token.ClientName, token.ID)

	// 返回加密的证书（包含客户端证书和CA证书）
	resp := EncryptedCertResponse{
		Success:       true,
		EncryptedCert: encryptedCert,
		EncryptedCA:   encryptedCA,
		Nonce:         nonce,
		CANonce:       caNonce,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// sendError 发送错误响应
func (api *CertAPIServer) sendError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(EncryptedCertResponse{
		Success: false,
		Error:   message,
	})
}

// signCertificate 签发证书
func (api *CertAPIServer) signCertificate(csr *x509.CertificateRequest) ([]byte, error) {
	// 生成序列号
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("生成序列号失败: %v", err)
	}

	// 创建证书模板
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour), // 1年有效期
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	// 签发证书
	certDER, err := x509.CreateCertificate(rand.Reader, &template, api.caCert, csr.PublicKey, api.caKey)
	if err != nil {
		return nil, fmt.Errorf("签发证书失败: %v", err)
	}

	// 编码为PEM格式
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return certPEM, nil
}

