//go:build windows
// +build windows

package main

import (
	"fmt"
	"log"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
)

// WintunAdapter 适配Wintun到water.Interface接口
type WintunAdapter struct {
	device tun.Device
	name   string
}

func (w *WintunAdapter) Read(p []byte) (n int, err error) {
	// Wintun的Read需要传入一个缓冲区数组
	bufs := [][]byte{p}
	sizes := []int{0}
	n, err = w.device.Read(bufs, sizes, 0)
	if err != nil {
		return 0, err
	}
	// 返回实际读取的字节数
	if len(sizes) > 0 {
		return sizes[0], nil
	}
	return 0, nil
}

func (w *WintunAdapter) Write(p []byte) (n int, err error) {
	// Wintun的Write需要传入缓冲区数组
	bufs := [][]byte{p}
	return w.device.Write(bufs, 0)
}

func (w *WintunAdapter) Close() error {
	return w.device.Close()
}

func (w *WintunAdapter) Name() string {
	return w.name
}

// checkRootPrivileges 检查是否具有管理员权限
func checkRootPrivileges() error {
	var sid *windows.SID

	// 创建管理员组的 SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid)
	if err != nil {
		return fmt.Errorf("检查权限失败: %v", err)
	}
	defer windows.FreeSid(sid)

	// 检查当前进程是否具有管理员权限
	token := windows.Token(0)
	member, err := token.IsMember(sid)
	if err != nil {
		return fmt.Errorf("检查权限失败: %v", err)
	}

	if !member {
		return fmt.Errorf("需要管理员权限运行，请右键选择'以管理员身份运行'")
	}

	return nil
}

// createTUNDevice 创建TUN设备（Windows版本 - 使用 Wintun）
func createTUNDevice(baseName string, network string) (TUNDevice, error) {
	log.Println("使用Wintun驱动创建TUN设备...")

	// 如果没有提供网络配置，使用默认值
	if network == "" {
		network = "10.8.0.0/24"
		log.Printf("未提供网络配置，使用默认值: %s", network)
	}

	// 创建Wintun TUN设备
	// Wintun是Layer 3设备，直接处理IP包
	tunDevice, err := tun.CreateTUN("tls-vpn", 1500)
	if err != nil {
		return nil, fmt.Errorf("创建Wintun设备失败: %v\n\n请确保:\n1. 以管理员身份运行\n2. Wintun驱动已安装（程序会自动加载）\n3. 如果问题持续，请从 https://www.wintun.net/ 下载Wintun", err)
	}

	// 获取设备名称
	name, err := tunDevice.Name()
	if err != nil {
		tunDevice.Close()
		return nil, fmt.Errorf("获取设备名称失败: %v", err)
	}

	log.Printf("成功创建Wintun TUN设备: %s", name)

	// 返回适配器（实现TUNDevice接口）
	adapter := &WintunAdapter{
		device: tunDevice,
		name:   name,
	}

	return adapter, nil
}

// configureTUNDevice 配置TUN设备IP地址（Windows版本）
func configureTUNDevice(ifaceName string, ipAddr string, mtu int) error {
	// 解析 IP 地址和 CIDR
	parts := strings.Split(ipAddr, "/")
	if len(parts) != 2 {
		return fmt.Errorf("无效的IP地址格式: %s，期望格式: x.x.x.x/xx", ipAddr)
	}

	ip := parts[0]
	cidr := parts[1]
	mask := cidrToNetmask(cidr)

	// 使用 netsh 命令配置 IP 地址
	log.Printf("配置TUN设备 %s: IP=%s, 掩码=%s", ifaceName, ip, mask)

	// 先尝试删除旧的 IP 配置
	_ = runCmdSilent("netsh", "interface", "ip", "delete", "address", ifaceName, ip)

	// 设置 IP 地址
	output, err := runCmdCombined("netsh", "interface", "ip", "set", "address",
		ifaceName, "static", ip, mask)
	if err != nil {
		// 尝试添加地址而不是设置
		output, err = runCmdCombined("netsh", "interface", "ip", "add", "address",
			ifaceName, ip, mask)
		if err != nil {
			return fmt.Errorf("设置IP地址失败: %v, 输出: %s", err, string(output))
		}
	}

	// 设置接口metric=1（禁用自动跃点数，确保路由优先级）
	output, err = runCmdCombined("netsh", "interface", "ipv4", "set", "interface",
		ifaceName, "metric=1")
	if err != nil {
		log.Printf("警告: 设置接口metric失败: %v, 输出: %s", err, string(output))
	} else {
		log.Printf("已设置接口 %s 的metric=1（最高优先级）", ifaceName)
	}

	// 设置 MTU
	output, err = runCmdCombined("netsh", "interface", "ipv4", "set", "subinterface",
		ifaceName, fmt.Sprintf("mtu=%d", mtu), "store=active")
	if err != nil {
		log.Printf("警告: 设置MTU失败: %v, 输出: %s", err, string(output))
		// MTU 设置失败不影响主要功能
	}

	log.Printf("配置TUN设备完成: %s IP=%s MTU=%d", ifaceName, ipAddr, mtu)
	return nil
}

// cleanupTUNDevice 清理TUN设备（Windows版本）
func cleanupTUNDevice(ifaceName string) {
	log.Printf("清理TUN设备: %s", ifaceName)
	// Wintun设备会在Close()时自动清理
}

// enableIPForwarding 启用IP转发（Windows版本）
func enableIPForwarding() error {
	// 使用注册表启用 IP 转发
	output, err := runCmdCombined("reg", "add",
		"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
		"/v", "IPEnableRouter", "/t", "REG_DWORD", "/d", "1", "/f")
	if err != nil {
		return fmt.Errorf("启用IP转发失败: %v, 输出: %s", err, string(output))
	}

	// 重启路由服务以应用更改
	_ = runCmdSilent("net", "stop", "RemoteAccess")
	output, err = runCmdCombined("net", "start", "RemoteAccess")
	if err != nil {
		log.Printf("警告: 启动RemoteAccess服务失败: %v", err)
		// 不是致命错误，继续
	}

	log.Println("已启用IP转发")
	return nil
}

// cidrToNetmask 将 CIDR 转换为子网掩码
func cidrToNetmask(cidr string) string {
	var bits int
	fmt.Sscanf(cidr, "%d", &bits)

	mask := uint32(0xFFFFFFFF) << (32 - bits)
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(mask>>24),
		byte(mask>>16),
		byte(mask>>8),
		byte(mask))
}

// getInterfaceIndex 获取网络接口索引
func getInterfaceIndex(ifaceName string) (int, error) {
	// 使用 netsh 命令获取接口信息
	output, err := exec.Command("netsh", "interface", "ipv4", "show", "interfaces").Output()
	if err != nil {
		return 0, fmt.Errorf("获取接口列表失败: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, ifaceName) {
			// 解析接口索引
			fields := strings.Fields(line)
			if len(fields) >= 1 {
				var idx int
				if _, err := fmt.Sscanf(fields[0], "%d", &idx); err == nil {
					return idx, nil
				}
			}
		}
	}

	return 0, fmt.Errorf("未找到接口: %s", ifaceName)
}

// getDefaultInterface 获取默认网络接口名称
func getDefaultInterface() (string, error) {
	// 使用 route print 获取默认路由接口
	output, err := exec.Command("route", "print", "0.0.0.0").Output()
	if err != nil {
		return "", fmt.Errorf("获取默认接口失败: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "0.0.0.0") {
			fields := strings.Fields(line)
			// route print 输出格式：网络 子网掩码 网关 接口 跃点
			if len(fields) >= 4 {
				return fields[3], nil
			}
		}
	}

	return "", fmt.Errorf("未找到默认接口")
}
