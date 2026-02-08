package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// Token Token既做认证凭证又做AES加密密钥
type Token struct {
	ID         string    `json:"id"`          // Token标识符
	Key        []byte    `json:"-"`           // 32字节密钥（不序列化到JSON）
	ClientName string    `json:"client_name"` // 客户端名称
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Used       bool      `json:"used"`
	UsedAt     time.Time `json:"used_at,omitempty"`
	UsedBy     string    `json:"used_by,omitempty"` // 使用者IP
}

// TokenManager Token管理器
type TokenManager struct {
	tokens map[string]*Token
	mutex  sync.RWMutex
}

// NewTokenManager 创建Token管理器
func NewTokenManager() *TokenManager {
	return &TokenManager{
		tokens: make(map[string]*Token),
	}
}

// NewTokenManagerWithLoad 创建Token管理器并加载已有Token
func NewTokenManagerWithLoad(tokenDir string) *TokenManager {
	tm := &TokenManager{
		tokens: make(map[string]*Token),
	}

	// 加载已有Token
	if err := tm.LoadTokensFromDir(tokenDir); err != nil {
		log.Printf("警告：加载Token文件失败: %v", err)
	}

	return tm
}

// LoadTokensFromDir 从目录加载Token文件
func (tm *TokenManager) LoadTokensFromDir(tokenDir string) error {
	files, err := os.ReadDir(tokenDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // 目录不存在，不是错误
		}
		return fmt.Errorf("读取Token目录失败: %v", err)
	}

	loaded := 0
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}

		path := tokenDir + "/" + file.Name()
		data, err := os.ReadFile(path)
		if err != nil {
			log.Printf("警告：读取Token文件失败 %s: %v", file.Name(), err)
			continue
		}

		var token Token
		if err := json.Unmarshal(data, &token); err != nil {
			log.Printf("警告：解析Token文件失败 %s: %v", file.Name(), err)
			continue
		}

		// 尝试读取带Key的格式
		keyHex, err := loadTokenKeyFromFile(path)
		if err != nil {
			log.Printf("警告：加载Token密钥失败 %s: %v", file.Name(), err)
			continue
		}
		token.Key, _ = hex.DecodeString(keyHex)

		tm.mutex.Lock()
		tm.tokens[token.ID] = &token
		tm.mutex.Unlock()
		loaded++
	}

	if loaded > 0 {
		log.Printf("已加载 %d 个Token", loaded)
	}
	return nil
}

// loadTokenKeyFromFile 从Token文件加载密钥
func loadTokenKeyFromFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	var tokenWithKey struct {
		Key string `json:"key_hex"`
	}
	if err := json.Unmarshal(data, &tokenWithKey); err == nil && tokenWithKey.Key != "" {
		return tokenWithKey.Key, nil
	}

	return "", fmt.Errorf("Token文件中没有密钥")
}

// GenerateToken 生成新Token
func (tm *TokenManager) GenerateToken(clientName string, duration time.Duration) (*Token, error) {
	// 生成32字节随机密钥（AES-256）
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("生成密钥失败: %v", err)
	}

	// 生成Token ID
	tokenID := fmt.Sprintf("%s-%s", clientName, time.Now().Format("20060102-150405"))

	token := &Token{
		ID:         tokenID,
		Key:        key,
		ClientName: clientName,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(duration),
		Used:       false,
	}

	tm.mutex.Lock()
	tm.tokens[tokenID] = token
	tm.mutex.Unlock()

	return token, nil
}

// GetToken 获取Token
func (tm *TokenManager) GetToken(tokenID string) (*Token, error) {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	token, exists := tm.tokens[tokenID]
	if !exists {
		return nil, fmt.Errorf("Token不存在")
	}

	return token, nil
}

// ValidateAndUseToken 验证并使用Token
func (tm *TokenManager) ValidateAndUseToken(tokenID, clientIP string) (*Token, error) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	log.Printf("[TokenManager] 验证Token: %s (来自: %s)", tokenID, clientIP)
	log.Printf("[TokenManager] 当前内存中Token数量: %d", len(tm.tokens))

	token, exists := tm.tokens[tokenID]
	if !exists {
		log.Printf("[TokenManager] Token不存在，当前可用Token ID列表:")
		for id := range tm.tokens {
			log.Printf("[TokenManager]   - %s", id)
		}
		return nil, fmt.Errorf("Token不存在")
	}

	// 检查是否已使用
	if token.Used {
		log.Printf("[TokenManager] Token已被使用: %s (使用时间: %s)", tokenID, token.UsedAt.Format("2006-01-02 15:04:05"))
		return nil, fmt.Errorf("Token已被使用（使用时间: %s, 使用者: %s）",
			token.UsedAt.Format("2006-01-02 15:04:05"), token.UsedBy)
	}

	// 检查是否过期
	if time.Now().After(token.ExpiresAt) {
		log.Printf("[TokenManager] Token已过期: %s (过期时间: %s)", tokenID, token.ExpiresAt.Format("2006-01-02 15:04:05"))
		return nil, fmt.Errorf("Token已过期")
	}

	// 标记已使用
	token.Used = true
	token.UsedAt = time.Now()
	token.UsedBy = clientIP

	log.Printf("[TokenManager] Token验证成功: %s (客户端: %s)", tokenID, token.ClientName)

	// 同步保存到文件（持久化使用状态）
	if err := tm.saveTokenToFile(token); err != nil {
		log.Printf("[TokenManager] 警告：保存Token状态失败: %v", err)
	}

	return token, nil
}

// saveTokenToFile 保存Token到文件
func (tm *TokenManager) saveTokenToFile(token *Token) error {
	tokenFile := fmt.Sprintf("%s/%s.json", DefaultTokenDir, token.ID)

	tokenData := struct {
		ID         string    `json:"id"`
		KeyHex     string    `json:"key_hex"`
		ClientName string    `json:"client_name"`
		CreatedAt  time.Time `json:"created_at"`
		ExpiresAt  time.Time `json:"expires_at"`
		Used       bool      `json:"used"`
		UsedAt     time.Time `json:"used_at,omitempty"`
		UsedBy     string    `json:"used_by,omitempty"`
	}{
		ID:         token.ID,
		KeyHex:     hex.EncodeToString(token.Key),
		ClientName: token.ClientName,
		CreatedAt:  token.CreatedAt,
		ExpiresAt:  token.ExpiresAt,
		Used:       token.Used,
		UsedAt:     token.UsedAt,
		UsedBy:     token.UsedBy,
	}

	data, err := json.MarshalIndent(tokenData, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化Token失败: %v", err)
	}

	return os.WriteFile(tokenFile, data, 0600)
}

// ListTokens 列出所有Token
func (tm *TokenManager) ListTokens() []*Token {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	tokens := make([]*Token, 0, len(tm.tokens))
	for _, token := range tm.tokens {
		tokens = append(tokens, token)
	}

	return tokens
}

// RevokeToken 撤销Token
func (tm *TokenManager) RevokeToken(tokenID string) error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	if _, exists := tm.tokens[tokenID]; !exists {
		return fmt.Errorf("Token不存在")
	}

	delete(tm.tokens, tokenID)
	return nil
}

// AddToken 添加Token到管理器（用于动态添加）
func (tm *TokenManager) AddToken(token *Token) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()
	tm.tokens[token.ID] = token
	log.Printf("[TokenManager] Token已添加到内存: %s (客户端: %s)", token.ID, token.ClientName)
}

// TokenCount 获取Token数量
func (tm *TokenManager) TokenCount() int {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()
	return len(tm.tokens)
}
