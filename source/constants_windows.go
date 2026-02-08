//go:build windows
// +build windows

package main

import (
	"os"
	"path/filepath"
)

// getControlSocketPath 获取控制 API 的路径（Windows版本）
// Windows 10 1803+ 支持 Unix socket，使用临时目录
func getControlSocketPath() string {
	tmpDir := os.TempDir()
	return filepath.Join(tmpDir, "vpn_control.sock")
}

// ControlSocketPath 控制 API 的路径（Windows版本）
// 使用初始化时计算的路径
var ControlSocketPath = getControlSocketPath()

// getDefaultLogPath 获取默认日志路径
func getDefaultLogPath() string {
	// 使用程序所在目录
	exePath, err := os.Executable()
	if err != nil {
		return "tls-vpn.log"
	}
	exeDir := filepath.Dir(exePath)
	return filepath.Join(exeDir, "tls-vpn.log")
}

// DefaultLogPath 默认日志路径
var DefaultLogPath = getDefaultLogPath()

// DefaultCertsDir 默认证书目录
const DefaultCertsDir = ".\\certs"

// DefaultTokensDir 默认 Token 目录
const DefaultTokensDir = ".\\tokens"
