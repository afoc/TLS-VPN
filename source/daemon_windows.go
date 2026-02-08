//go:build windows
// +build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// startDaemon 启动 daemon 进程（Windows版本）
func startDaemon() error {
	// 获取当前可执行文件路径
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("获取可执行文件路径失败: %v", err)
	}

	// 创建子进程
	cmd := exec.Command(executable, "--service")

	// Windows 上使用 CREATE_NEW_PROCESS_GROUP 和隐藏窗口
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
		HideWindow:    true,
	}

	// 不继承标准输入输出（daemon 有自己的日志）
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil

	// 启动进程
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动进程失败: %v", err)
	}

	// 立即释放子进程（不等待它结束）
	go cmd.Wait()

	return nil
}
