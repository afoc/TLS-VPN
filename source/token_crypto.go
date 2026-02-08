package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

// EncryptedCertRequest 加密的证书请求
type EncryptedCertRequest struct {
	TokenID      string `json:"token_id"`
	EncryptedCSR []byte `json:"encrypted_csr"`
	Nonce        []byte `json:"nonce"`
}

// EncryptedCertResponse 加密的证书响应
type EncryptedCertResponse struct {
	Success       bool   `json:"success"`
	EncryptedCert []byte `json:"encrypted_cert,omitempty"`
	EncryptedCA   []byte `json:"encrypted_ca,omitempty"` // 新增：加密的CA证书
	Nonce         []byte `json:"nonce,omitempty"`
	CANonce       []byte `json:"ca_nonce,omitempty"` // 新增：CA证书的nonce
	Error         string `json:"error,omitempty"`
}

// EncryptWithToken 使用Token密钥加密数据（AES-256-GCM）
func EncryptWithToken(data []byte, tokenKey []byte) (ciphertext, nonce []byte, err error) {
	// 创建AES cipher
	block, err := aes.NewCipher(tokenKey)
	if err != nil {
		return nil, nil, fmt.Errorf("创建cipher失败: %v", err)
	}

	// 创建GCM模式（带认证的加密）
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("创建GCM失败: %v", err)
	}

	// 生成随机nonce
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("生成nonce失败: %v", err)
	}

	// 加密并认证
	ciphertext = gcm.Seal(nil, nonce, data, nil)

	return ciphertext, nonce, nil
}

// DecryptWithToken 使用Token密钥解密数据
func DecryptWithToken(ciphertext, nonce, tokenKey []byte) ([]byte, error) {
	// 创建AES cipher
	block, err := aes.NewCipher(tokenKey)
	if err != nil {
		return nil, fmt.Errorf("创建cipher失败: %v", err)
	}

	// 创建GCM模式
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("创建GCM失败: %v", err)
	}

	// 解密并验证认证标签
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("解密失败或数据被篡改: %v", err)
	}

	return plaintext, nil
}
