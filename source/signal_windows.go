//go:build windows
// +build windows

package main

import (
	"os"
	"os/signal"
)

// setupSignalHandler 设置信号处理（Windows版本）
func setupSignalHandler() chan os.Signal {
	sigChan := make(chan os.Signal, 1)
	// Windows 上使用 os.Interrupt 代替 syscall.SIGINT
	signal.Notify(sigChan, os.Interrupt)
	return sigChan
}
