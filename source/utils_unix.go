//go:build !windows
// +build !windows

package main

import (
	"fmt"
	"log"
	"os"
	"syscall"
)

// ================ PID 文件管理 (Unix/Linux 版本) ================

// createPIDFile 创建PID文件（防止多实例运行）
func createPIDFile(pidFile string) error {
	// 检查PID文件是否已存在
	if data, err := os.ReadFile(pidFile); err == nil {
		// PID文件存在，检查进程是否还在运行
		var oldPID int
		if _, err := fmt.Sscanf(string(data), "%d", &oldPID); err == nil {
			// 检查进程是否存在
			process, err := os.FindProcess(oldPID)
			if err == nil {
				// 尝试发送信号0来检查进程是否存在
				if err := process.Signal(syscall.Signal(0)); err == nil {
					return fmt.Errorf("程序已在运行 (PID: %d)，如果确认没有运行，请删除: %s", oldPID, pidFile)
				}
			}
			// 进程不存在，清理旧的PID文件
			log.Printf("检测到旧的PID文件 (PID: %d 已不存在)，正在清理...", oldPID)
			os.Remove(pidFile)
		}
	}

	// 写入当前进程PID
	pid := os.Getpid()
	if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d\n", pid)), 0644); err != nil {
		return fmt.Errorf("创建PID文件失败: %v", err)
	}

	log.Printf("已创建PID文件: %s (PID: %d)", pidFile, pid)
	return nil
}

// removePIDFile 删除PID文件
func removePIDFile(pidFile string) {
	if err := os.Remove(pidFile); err != nil {
		log.Printf("警告: 删除PID文件失败: %v", err)
	} else {
		log.Printf("已删除PID文件: %s", pidFile)
	}
}
