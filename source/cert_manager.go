package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

// CertificatePair 证书对
type CertificatePair struct {
	Certificate tls.Certificate
	CAPool      *x509.CertPool
}

// CertificateManager 证书管理器
type CertificateManager struct {
	ServerCert CertificatePair
	ClientCert CertificatePair
	caCert     *x509.Certificate
}

// generateCACertificate 生成CA证书
func generateCACertificate() ([]byte, []byte, *x509.Certificate, *rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("生成CA私钥失败: %v", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("生成CA序列号失败: %v", err)
	}

	caTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"SecureVPN Organization"},
			Country:      []string{"CN"},
			Province:     []string{"Beijing"},
			Locality:     []string{"Beijing"},
			CommonName:   "VPN-CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years for CA
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	caCertBytes, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("生成CA证书失败: %v", err)
	}

	caCert, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("解析CA证书失败: %v", err)
	}

	caCertPEM := pemEncode("CERTIFICATE", caCertBytes)
	caKeyPEM := pemEncode("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(privateKey))

	return caCertPEM, caKeyPEM, caCert, privateKey, nil
}

// generateCertificatePair 生成由CA签名的证书对
func generateCertificatePair(isServer bool, caCert *x509.Certificate, caKey *rsa.PrivateKey) ([]byte, []byte, error) {
	if caCert == nil || caKey == nil {
		return nil, nil, fmt.Errorf("CA证书和私钥不能为空")
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, fmt.Errorf("生成私钥失败: %v", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("生成序列号失败: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"SecureVPN Organization"},
			Country:      []string{"CN"},
			Province:     []string{"Beijing"},
			Locality:     []string{"Beijing"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	if isServer {
		template.Subject.CommonName = "vpn-server"
		template.DNSNames = []string{"localhost", "vpn-server"}
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	} else {
		template.Subject.CommonName = "vpn-client"
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &privateKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("生成证书失败: %v", err)
	}

	certPEM := pemEncode("CERTIFICATE", certDER)
	privateKeyPEM := pemEncode("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(privateKey))

	return certPEM, privateKeyPEM, nil
}

// pemEncode 将数据编码为PEM格式
func pemEncode(blockType string, data []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  blockType,
		Bytes: data,
	})
}

// ServerCertificatesExist 检查服务器证书是否存在（只检查服务器所需证书）
func ServerCertificatesExist(certDir string) bool {
	files := []string{
		certDir + "/ca.pem",
		certDir + "/server.pem",
		certDir + "/server-key.pem",
	}

	for _, file := range files {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// CertificatesExist 检查证书文件是否存在（完整检查，包含客户端证书，用于向后兼容）
func CertificatesExist(certDir string) bool {
	files := []string{
		certDir + "/ca.pem",
		certDir + "/server.pem",
		certDir + "/server-key.pem",
		certDir + "/client.pem",
		certDir + "/client-key.pem",
	}

	for _, file := range files {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// ClientCertificatesExist 检查客户端证书是否存在（只检查ca.pem, client.pem, client-key.pem）
func ClientCertificatesExist(certDir string) bool {
	files := []string{
		certDir + "/ca.pem",
		certDir + "/client.pem",
		certDir + "/client-key.pem",
	}

	for _, file := range files {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// LoadCertificateManagerForClient 为客户端加载证书（不会自动生成）
func LoadCertificateManagerForClient(certDir string) (*CertificateManager, error) {
	// 检查客户端必需的证书文件
	if !ClientCertificatesExist(certDir) {
		// 列出缺失的文件
		missing := []string{}
		files := map[string]string{
			certDir + "/ca.pem":         "CA证书",
			certDir + "/client.pem":     "客户端证书",
			certDir + "/client-key.pem": "客户端私钥",
		}
		for file, name := range files {
			if _, err := os.Stat(file); os.IsNotExist(err) {
				missing = append(missing, name+" ("+file+")")
			}
		}
		return nil, fmt.Errorf("客户端证书不完整，缺少以下文件:\n  - %s\n\n请运行 ./vpn 进入菜单，选择 '证书管理' -> 'Token申请证书' 来申请证书", strings.Join(missing, "\n  - "))
	}

	// 读取CA证书
	caCertPEM, err := os.ReadFile(certDir + "/ca.pem")
	if err != nil {
		return nil, fmt.Errorf("读取CA证书失败: %v", err)
	}

	// 解析CA证书
	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		return nil, fmt.Errorf("解码CA证书失败")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析CA证书失败: %v", err)
	}

	// 读取客户端证书和私钥
	clientCertPEM, err := os.ReadFile(certDir + "/client.pem")
	if err != nil {
		return nil, fmt.Errorf("读取客户端证书失败: %v", err)
	}
	clientKeyPEM, err := os.ReadFile(certDir + "/client-key.pem")
	if err != nil {
		return nil, fmt.Errorf("读取客户端私钥失败: %v", err)
	}

	// 创建客户端证书对
	clientCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("加载客户端证书失败: %v", err)
	}

	clientCAPool := x509.NewCertPool()
	clientCAPool.AppendCertsFromPEM(caCertPEM)

	// 客户端模式不需要服务器证书，使用空的服务器证书
	return &CertificateManager{
		ServerCert: CertificatePair{
			CAPool: clientCAPool, // 用于验证服务器
		},
		ClientCert: CertificatePair{
			Certificate: clientCert,
			CAPool:      clientCAPool,
		},
		caCert: caCert,
	}, nil
}

// SaveServerCertificates 保存服务器证书到文件（不包含客户端证书）
func SaveServerCertificates(certDir string, caCertPEM, serverCertPEM, serverKeyPEM []byte) error {
	// 创建证书目录
	if err := os.MkdirAll(certDir, 0700); err != nil { // 改为0700更安全
		return fmt.Errorf("创建证书目录失败: %v", err)
	}

	// 保存CA证书 (0644)
	if err := os.WriteFile(certDir+"/ca.pem", caCertPEM, 0644); err != nil {
		return fmt.Errorf("保存CA证书失败: %v", err)
	}

	// 保存服务器证书 (0644)
	if err := os.WriteFile(certDir+"/server.pem", serverCertPEM, 0644); err != nil {
		return fmt.Errorf("保存服务器证书失败: %v", err)
	}

	// 保存服务器私钥 (0600)
	if err := os.WriteFile(certDir+"/server-key.pem", serverKeyPEM, 0600); err != nil {
		return fmt.Errorf("保存服务器私钥失败: %v", err)
	}

	return nil
}

// SaveCertificates 保存证书到文件（包含客户端证书，用于向后兼容）
func SaveCertificates(certDir string, caCertPEM, serverCertPEM, serverKeyPEM, clientCertPEM, clientKeyPEM []byte) error {
	// 先保存服务器证书
	if err := SaveServerCertificates(certDir, caCertPEM, serverCertPEM, serverKeyPEM); err != nil {
		return err
	}

	// 保存客户端证书 (0644)
	if err := os.WriteFile(certDir+"/client.pem", clientCertPEM, 0644); err != nil {
		return fmt.Errorf("保存客户端证书失败: %v", err)
	}

	// 保存客户端私钥 (0600)
	if err := os.WriteFile(certDir+"/client-key.pem", clientKeyPEM, 0600); err != nil {
		return fmt.Errorf("保存客户端私钥失败: %v", err)
	}

	return nil
}

// SaveCAKey 保存CA私钥（用于签发证书）
func SaveCAKey(certDir string, caKeyPEM []byte) error {
	// 保存CA私钥 (0400 - 只读，仅owner)
	if err := os.WriteFile(certDir+"/ca-key.pem", caKeyPEM, 0400); err != nil {
		return fmt.Errorf("保存CA私钥失败: %v", err)
	}
	return nil
}

// LoadCAKey 加载CA私钥
func LoadCAKey(certDir string) (*rsa.PrivateKey, error) {
	caKeyPEM, err := os.ReadFile(certDir + "/ca-key.pem")
	if err != nil {
		return nil, fmt.Errorf("读取CA私钥失败: %v", err)
	}

	block, _ := pem.Decode(caKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("解码CA私钥失败")
	}

	caKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析CA私钥失败: %v", err)
	}

	return caKey, nil
}

// LoadServerCertificateManager 从文件加载服务器证书（只加载服务器所需证书）
func LoadServerCertificateManager(certDir string) (*CertificateManager, error) {
	// 读取CA证书
	caCertPEM, err := os.ReadFile(certDir + "/ca.pem")
	if err != nil {
		return nil, fmt.Errorf("读取CA证书失败: %v", err)
	}

	// 解析CA证书
	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		return nil, fmt.Errorf("解码CA证书失败")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析CA证书失败: %v", err)
	}

	// 读取服务器证书和私钥
	serverCertPEM, err := os.ReadFile(certDir + "/server.pem")
	if err != nil {
		return nil, fmt.Errorf("读取服务器证书失败: %v", err)
	}
	serverKeyPEM, err := os.ReadFile(certDir + "/server-key.pem")
	if err != nil {
		return nil, fmt.Errorf("读取服务器私钥失败: %v", err)
	}

	// 创建服务器证书对
	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("加载服务器证书失败: %v", err)
	}

	serverCAPool := x509.NewCertPool()
	serverCAPool.AppendCertsFromPEM(caCertPEM)

	// 服务端模式不需要客户端证书
	return &CertificateManager{
		ServerCert: CertificatePair{
			Certificate: serverCert,
			CAPool:      serverCAPool,
		},
		ClientCert: CertificatePair{
			// 空的客户端证书，服务端不使用
			CAPool: serverCAPool,
		},
		caCert: caCert,
	}, nil
}

// LoadCertificateManagerFromFiles 从文件加载证书（包含客户端证书，用于向后兼容）
func LoadCertificateManagerFromFiles(certDir string) (*CertificateManager, error) {
	// 读取CA证书
	caCertPEM, err := os.ReadFile(certDir + "/ca.pem")
	if err != nil {
		return nil, fmt.Errorf("读取CA证书失败: %v", err)
	}

	// 解析CA证书
	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		return nil, fmt.Errorf("解码CA证书失败")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析CA证书失败: %v", err)
	}

	// 读取服务器证书和私钥
	serverCertPEM, err := os.ReadFile(certDir + "/server.pem")
	if err != nil {
		return nil, fmt.Errorf("读取服务器证书失败: %v", err)
	}
	serverKeyPEM, err := os.ReadFile(certDir + "/server-key.pem")
	if err != nil {
		return nil, fmt.Errorf("读取服务器私钥失败: %v", err)
	}

	// 读取客户端证书和私钥
	clientCertPEM, err := os.ReadFile(certDir + "/client.pem")
	if err != nil {
		return nil, fmt.Errorf("读取客户端证书失败: %v", err)
	}
	clientKeyPEM, err := os.ReadFile(certDir + "/client-key.pem")
	if err != nil {
		return nil, fmt.Errorf("读取客户端私钥失败: %v", err)
	}

	// 创建服务器证书对
	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("加载服务器证书失败: %v", err)
	}

	serverCAPool := x509.NewCertPool()
	serverCAPool.AppendCertsFromPEM(caCertPEM)

	// 创建客户端证书对
	clientCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("加载客户端证书失败: %v", err)
	}

	clientCAPool := x509.NewCertPool()
	clientCAPool.AppendCertsFromPEM(caCertPEM)

	return &CertificateManager{
		ServerCert: CertificatePair{
			Certificate: serverCert,
			CAPool:      serverCAPool,
		},
		ClientCert: CertificatePair{
			Certificate: clientCert,
			CAPool:      clientCAPool,
		},
		caCert: caCert,
	}, nil
}

// NewCertificateManager 创建证书管理器（服务端模式）
func NewCertificateManager() (*CertificateManager, error) {
	// 检查服务器证书文件是否存在
	if ServerCertificatesExist(DefaultCertDir) {
		log.Printf("从 %s 目录加载已有服务器证书", DefaultCertDir)
		return LoadServerCertificateManager(DefaultCertDir)
	}

	// 证书不存在，生成新证书
	log.Println("服务器证书文件不存在，生成新证书...")

	// 首先生成CA证书
	caCertPEM, caKeyPEM, caCert, caKey, err := generateCACertificate()
	if err != nil {
		return nil, fmt.Errorf("生成CA证书失败: %v", err)
	}

	// 生成服务器证书
	serverCertPEM, serverKeyPEM, err := generateCertificatePair(true, caCert, caKey)
	if err != nil {
		return nil, fmt.Errorf("生成服务器证书失败: %v", err)
	}

	// 注意: 客户端证书不在此处生成，而是通过Token+CSR机制动态签发
	// 这样每个客户端都有独立的证书，符合安全最佳实践

	// 保存证书到文件（只保存CA和服务器证书）
	if err := SaveServerCertificates(DefaultCertDir, caCertPEM, serverCertPEM, serverKeyPEM); err != nil {
		return nil, fmt.Errorf("保存证书失败: %v", err)
	}

	// 保存CA私钥（用于签发新证书）
	if err := SaveCAKey(DefaultCertDir, caKeyPEM); err != nil {
		return nil, fmt.Errorf("保存CA私钥失败: %v", err)
	}

	log.Printf("证书已生成并保存到 %s 目录", DefaultCertDir)

	// 创建服务器证书对
	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("加载服务器证书失败: %v", err)
	}

	serverCAPool := x509.NewCertPool()
	serverCAPool.AppendCertsFromPEM(caCertPEM)

	// 服务端模式不需要客户端证书
	// 客户端证书通过Token+CSR机制动态签发
	return &CertificateManager{
		ServerCert: CertificatePair{
			Certificate: serverCert,
			CAPool:      serverCAPool,
		},
		ClientCert: CertificatePair{
			// 空的客户端证书，服务端不使用
			CAPool: serverCAPool,
		},
		caCert: caCert,
	}, nil
}

// ServerTLSConfig 服务器TLS配置
func (cm *CertificateManager) ServerTLSConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cm.ServerCert.Certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    cm.ServerCert.CAPool,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}
}

// ClientTLSConfig 客户端TLS配置
func (cm *CertificateManager) ClientTLSConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cm.ClientCert.Certificate},
		RootCAs:      cm.ClientCert.CAPool,
		ServerName:   "vpn-server",
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}
}
