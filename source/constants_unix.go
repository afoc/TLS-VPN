//go:build !windows
// +build !windows

package main

// ControlSocketPath 控制 API 的 Unix Socket 路径（Linux/Unix版本）
const ControlSocketPath = "/var/run/vpn_control.sock"

// DefaultLogPath 默认日志路径
const DefaultLogPath = "/var/log/tls-vpn.log"

// DefaultCertsDir 默认证书目录
const DefaultCertsDir = "./certs"

// DefaultTokensDir 默认 Token 目录
const DefaultTokensDir = "./tokens"
