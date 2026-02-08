package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// TokenFile Token 文件结构（用于读取保存的 Token 文件）
type TokenFile struct {
	ID         string `json:"id"`
	KeyHex     string `json:"key_hex"` // 十六进制密钥
	ClientName string `json:"client_name"`
}

// readTokenFromFile 从文件读取Token信息，返回 (tokenID, tokenKeyHex)
func readTokenFromFile(tokenFile string) (tokenID, tokenKey string, err error) {
	data, err := os.ReadFile(tokenFile)
	if err != nil {
		return "", "", fmt.Errorf("读取Token文件失败: %v", err)
	}

	var token TokenFile
	if err := json.Unmarshal(data, &token); err != nil {
		return "", "", fmt.Errorf("解析Token文件失败: %v", err)
	}

	if token.ID == "" || token.KeyHex == "" {
		return "", "", fmt.Errorf("Token文件格式错误：缺少id或key_hex字段")
	}

	return token.ID, token.KeyHex, nil
}
