//go:build !windows
// +build !windows

package main

import (
	"os"
	"os/signal"
	"syscall"
)

// setupSignalHandler 设置信号处理（Unix/Linux版本）
func setupSignalHandler() chan os.Signal {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	return sigChan
}
