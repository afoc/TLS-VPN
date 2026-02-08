//go:build windows
// +build windows

package main

import (
	"fmt"
	"log"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ================ PID 文件管理 (Windows 版本) ================

// createPIDFile 创建PID文件（Windows版本）
func createPIDFile(pidFile string) error {
	// 检查PID文件是否已存在
	if data, err := os.ReadFile(pidFile); err == nil {
		// PID文件存在，检查进程是否还在运行
		var oldPID int
		if _, err := fmt.Sscanf(string(data), "%d", &oldPID); err == nil {
			// Windows 上检查进程是否存在
			handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(oldPID))
			if err == nil {
				// 进程存在
				windows.CloseHandle(handle)
				return fmt.Errorf("程序已在运行 (PID: %d)，如果确认没有运行，请删除: %s", oldPID, pidFile)
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

// ================ Windows 特定工具函数 ================

// isRunningAsAdmin 检查是否以管理员身份运行
func isRunningAsAdmin() bool {
	var sid *windows.SID

	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	token := windows.Token(0)
	member, err := token.IsMember(sid)
	if err != nil {
		return false
	}

	return member
}

// runAsAdmin 请求以管理员身份运行
func runAsAdmin() error {
	verb := "runas"
	exe, _ := os.Executable()
	cwd, _ := os.Getwd()

	verbPtr, _ := syscall.UTF16PtrFromString(verb)
	exePtr, _ := syscall.UTF16PtrFromString(exe)
	cwdPtr, _ := syscall.UTF16PtrFromString(cwd)

	var showCmd int32 = 1 // SW_NORMAL

	err := windows.ShellExecute(0, verbPtr, exePtr, nil, cwdPtr, showCmd)
	if err != nil {
		return fmt.Errorf("请求管理员权限失败: %v", err)
	}

	return nil
}

// getWindowsVersion 获取 Windows 版本信息
func getWindowsVersion() string {
	// 使用 RtlGetVersion 获取真实版本
	type rtlOSVersionInfoEx struct {
		OSVersionInfoSize uint32
		MajorVersion      uint32
		MinorVersion      uint32
		BuildNumber       uint32
		PlatformId        uint32
		CSDVersion        [128]uint16
	}

	var version rtlOSVersionInfoEx
	version.OSVersionInfoSize = uint32(unsafe.Sizeof(version))

	// 尝试使用 ntdll.dll 的 RtlGetVersion
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	rtlGetVersion := ntdll.NewProc("RtlGetVersion")

	if rtlGetVersion.Find() == nil {
		rtlGetVersion.Call(uintptr(unsafe.Pointer(&version)))
		return fmt.Sprintf("Windows %d.%d (Build %d)",
			version.MajorVersion, version.MinorVersion, version.BuildNumber)
	}

	return "Windows (版本未知)"
}

// configureWindowsFirewall 配置 Windows 防火墙规则
func configureWindowsFirewall(ruleName string, port int, protocol string) error {
	// 先删除可能存在的同名规则
	_ = runCmdSilent("netsh", "advfirewall", "firewall", "delete", "rule", fmt.Sprintf("name=%s", ruleName))

	// 添加入站规则
	output, err := runCmdCombined("netsh", "advfirewall", "firewall", "add", "rule",
		fmt.Sprintf("name=%s", ruleName),
		"dir=in",
		"action=allow",
		fmt.Sprintf("protocol=%s", protocol),
		fmt.Sprintf("localport=%d", port))
	if err != nil {
		return fmt.Errorf("添加防火墙规则失败: %v, 输出: %s", err, string(output))
	}

	log.Printf("已添加防火墙规则: %s (端口 %d/%s)", ruleName, port, protocol)
	return nil
}

// removeWindowsFirewallRule 删除 Windows 防火墙规则
func removeWindowsFirewallRule(ruleName string) error {
	output, err := runCmdCombined("netsh", "advfirewall", "firewall", "delete", "rule",
		fmt.Sprintf("name=%s", ruleName))
	if err != nil {
		return fmt.Errorf("删除防火墙规则失败: %v, 输出: %s", err, string(output))
	}

	log.Printf("已删除防火墙规则: %s", ruleName)
	return nil
}

// enableWindowsNetworkAdapter 启用网络适配器
func enableWindowsNetworkAdapter(adapterName string) error {
	output, err := runCmdCombined("netsh", "interface", "set", "interface",
		adapterName, "admin=enabled")
	if err != nil {
		return fmt.Errorf("启用网络适配器失败: %v, 输出: %s", err, string(output))
	}
	return nil
}

// disableWindowsNetworkAdapter 禁用网络适配器
func disableWindowsNetworkAdapter(adapterName string) error {
	output, err := runCmdCombined("netsh", "interface", "set", "interface",
		adapterName, "admin=disabled")
	if err != nil {
		return fmt.Errorf("禁用网络适配器失败: %v, 输出: %s", err, string(output))
	}
	return nil
}

// flushDNSCache 刷新 DNS 缓存
func flushDNSCache() error {
	output, err := runCmdCombined("ipconfig", "/flushdns")
	if err != nil {
		return fmt.Errorf("刷新DNS缓存失败: %v, 输出: %s", err, string(output))
	}
	log.Println("已刷新DNS缓存")
	return nil
}
