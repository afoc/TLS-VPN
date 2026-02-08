//go:build windows
// +build windows

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// RouteEntry 路由条目
type RouteEntry struct {
	Destination string
	Gateway     string
	Interface   string
	Metric      int
}

// RouteManager 路由管理器（Windows版本）
type RouteManager struct {
	installedRoutes []RouteEntry
	originalDNS     []string
	defaultGateway  string
	defaultIface    string
	mutex           sync.Mutex
}

// NewRouteManager 创建路由管理器并自动检测默认网关
func NewRouteManager() (*RouteManager, error) {
	rm := &RouteManager{
		installedRoutes: make([]RouteEntry, 0),
		originalDNS:     make([]string, 0),
	}

	// 检测默认网关和接口
	if err := rm.detectDefaultGateway(); err != nil {
		return nil, fmt.Errorf("检测默认网关失败: %v", err)
	}

	log.Printf("检测到默认网关: %s (接口: %s)", rm.defaultGateway, rm.defaultIface)
	return rm, nil
}

// detectDefaultGateway 检测默认网关（Windows版本）
func (rm *RouteManager) detectDefaultGateway() error {
	// 使用 route print 命令获取默认路由
	output, err := exec.Command("route", "print", "0.0.0.0", "mask", "0.0.0.0").Output()
	if err != nil {
		// 尝试使用 netsh 命令
		return rm.detectDefaultGatewayNetsh()
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// 查找包含 0.0.0.0 的行（默认路由）
		if strings.HasPrefix(line, "0.0.0.0") {
			fields := strings.Fields(line)
			// Windows route print 格式：网络 子网掩码 网关 接口 跃点
			if len(fields) >= 5 {
				rm.defaultGateway = fields[2]
				rm.defaultIface = fields[3]
				return nil
			}
		}
	}

	// 如果上面的方法失败，尝试使用 netsh
	return rm.detectDefaultGatewayNetsh()
}

// detectDefaultGatewayNetsh 使用 netsh 检测默认网关
func (rm *RouteManager) detectDefaultGatewayNetsh() error {
	output, err := exec.Command("netsh", "interface", "ipv4", "show", "route").Output()
	if err != nil {
		return fmt.Errorf("执行netsh命令失败: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// 查找默认路由 0.0.0.0/0
		if strings.Contains(line, "0.0.0.0/0") {
			fields := strings.Fields(line)
			// 查找网关和接口
			for i, field := range fields {
				// 网关通常是一个 IP 地址
				if isIPv4(field) && rm.defaultGateway == "" {
					rm.defaultGateway = field
				}
				// 接口名通常在后面
				if i > 0 && rm.defaultIface == "" && !isIPv4(field) && !strings.HasPrefix(field, "0.0.0.0") {
					rm.defaultIface = field
				}
			}
			if rm.defaultGateway != "" {
				return nil
			}
		}
	}

	// 最后尝试：使用 ipconfig 获取默认网关
	return rm.detectDefaultGatewayIpconfig()
}

// detectDefaultGatewayIpconfig 使用 ipconfig 检测默认网关
func (rm *RouteManager) detectDefaultGatewayIpconfig() error {
	output, err := exec.Command("ipconfig").Output()
	if err != nil {
		return fmt.Errorf("执行ipconfig命令失败: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	var currentAdapter string

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// 检测适配器名称
		if strings.HasSuffix(line, ":") && !strings.Contains(line, ".") {
			currentAdapter = strings.TrimSuffix(line, ":")
		}

		// 检测默认网关
		if strings.Contains(line, "Default Gateway") || strings.Contains(line, "默认网关") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				gateway := strings.TrimSpace(parts[len(parts)-1])
				if isIPv4(gateway) {
					rm.defaultGateway = gateway
					rm.defaultIface = currentAdapter
					return nil
				}
			}
		}
	}

	if rm.defaultGateway == "" {
		return fmt.Errorf("无法检测到默认网关")
	}

	return nil
}

// isIPv4 检查字符串是否是有效的 IPv4 地址
func isIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		var n int
		if _, err := fmt.Sscanf(part, "%d", &n); err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}

// AddRoute 添加路由（Windows版本 - 使用netsh命令）
func (rm *RouteManager) AddRoute(destination, gateway, iface string) error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	// 如果提供了接口名称，使用netsh命令（支持接口名称，更可靠）
	if iface != "" {
		// 使用netsh interface ipv4 add route命令
		// 格式: netsh interface ipv4 add route <CIDR> <接口名> <网关> metric=1
		output, err := runCmdCombined("netsh", "interface", "ipv4", "add", "route",
			destination, iface, gateway, "metric=1")
		
		if err != nil {
			outputStr := string(output)
			// 检查是否是因为路由已存在
			if strings.Contains(outputStr, "对象已存在") ||
				strings.Contains(outputStr, "The object already exists") ||
				strings.Contains(outputStr, "already exists") {
				log.Printf("路由 %s 已存在，跳过", destination)
				return nil
			}
			return fmt.Errorf("添加路由失败: %v, 输出: %s", err, outputStr)
		}

		// 记录已安装的路由
		rm.installedRoutes = append(rm.installedRoutes, RouteEntry{
			Destination: destination,
			Gateway:     gateway,
			Interface:   iface,
		})

		log.Printf("已添加路由: %s via %s (接口: %s, metric=1)", destination, gateway, iface)
		return nil
	}

	// 如果没有指定接口，使用传统route命令
	ip, mask := parseCIDR(destination)
	args := []string{"add", ip, "mask", mask}

	if gateway != "" {
		args = append(args, gateway)
	}
	args = append(args, "metric", "1")

	cmd := exec.Command("route", args...)
	output, err := cmd.CombinedOutput()

	if err != nil {
		outputStr := string(output)
		if strings.Contains(outputStr, "对象已存在") ||
			strings.Contains(outputStr, "The object already exists") ||
			strings.Contains(outputStr, "already exists") {
			log.Printf("路由 %s 已存在，跳过", destination)
			return nil
		}
		return fmt.Errorf("添加路由失败: %v, 输出: %s", err, outputStr)
	}

	rm.installedRoutes = append(rm.installedRoutes, RouteEntry{
		Destination: destination,
		Gateway:     gateway,
		Interface:   iface,
	})

	log.Printf("已添加路由: %s via %s", destination, gateway)
	return nil
}

// DeleteRoute 删除路由（Windows版本）
func (rm *RouteManager) DeleteRoute(destination string) error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	ip, mask := parseCIDR(destination)

	cmd := exec.Command("route", "delete", ip, "mask", mask)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("删除路由失败: %v, 输出: %s", err, string(output))
	}

	log.Printf("已删除路由: %s", destination)
	return nil
}

// CleanupRoutes 清理所有已安装的路由（Windows版本）
func (rm *RouteManager) CleanupRoutes() {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	for _, route := range rm.installedRoutes {
		ip, mask := parseCIDR(route.Destination)
		output, err := runCmdCombined("route", "delete", ip, "mask", mask)
		if err != nil {
			log.Printf("警告：删除路由 %s 失败: %v, 输出: %s", route.Destination, err, string(output))
		} else {
			log.Printf("已清理路由: %s", route.Destination)
		}
	}

	rm.installedRoutes = make([]RouteEntry, 0)
}

// SaveDNS 保存原始DNS配置（Windows版本）
func (rm *RouteManager) SaveDNS() error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	// 获取当前 DNS 配置
	output, err := exec.Command("netsh", "interface", "ipv4", "show", "dnsservers").Output()
	if err != nil {
		return fmt.Errorf("获取DNS配置失败: %v", err)
	}

	// 解析 DNS 服务器
	lines := strings.Split(string(output), "\n")
	rm.originalDNS = make([]string, 0)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		// 查找 DNS 服务器 IP
		if isIPv4(line) {
			rm.originalDNS = append(rm.originalDNS, line)
		} else if strings.Contains(line, ":") {
			// 格式可能是 "DNS 服务器: x.x.x.x"
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				ip := strings.TrimSpace(parts[len(parts)-1])
				if isIPv4(ip) {
					rm.originalDNS = append(rm.originalDNS, ip)
				}
			}
		}
	}

	// 备份到文件
	backupPath := filepath.Join(os.TempDir(), "vpn_dns_backup.txt")
	content := strings.Join(rm.originalDNS, "\n")
	if err := os.WriteFile(backupPath, []byte(content), 0644); err != nil {
		log.Printf("警告: 备份DNS配置到文件失败: %v", err)
	}

	log.Printf("已保存原始DNS配置: %v", rm.originalDNS)
	return nil
}

// SetDNS 设置DNS服务器（Windows版本）
// 注意：此函数需要接收VPN接口名称来正确设置DNS
func (rm *RouteManager) SetDNS(dnsServers []string) error {
	return rm.SetDNSForInterface(dnsServers, "")
}

// SetDNSForInterface 为指定接口设置DNS服务器
func (rm *RouteManager) SetDNSForInterface(dnsServers []string, vpnIface string) error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	if len(dnsServers) == 0 {
		return nil
	}

	// 如果指定了VPN接口，优先在VPN接口上设置DNS
	// 否则在默认接口上设置（保持向后兼容）
	ifaceName := vpnIface
	if ifaceName == "" {
		ifaceName = rm.defaultIface
		if ifaceName == "" {
			ifaceName = "以太网" // 默认尝试
		}
	}

	log.Printf("正在为接口 %s 设置DNS服务器...", ifaceName)

	// 设置主 DNS
	output, err := runCmdCombined("netsh", "interface", "ipv4", "set", "dnsservers",
		ifaceName, "static", dnsServers[0], "primary")
	if err != nil {
		// 如果是VPN接口，可能需要尝试不同的命令
		if vpnIface != "" {
			log.Printf("警告: 在VPN接口设置主DNS失败: %v, 输出: %s", err, string(output))
			// 尝试备选方法：使用netsh interface ip命令
			output, err = runCmdCombined("netsh", "interface", "ip", "set", "dns",
				ifaceName, "static", dnsServers[0])
			if err != nil {
				return fmt.Errorf("设置VPN接口DNS失败: %v, 输出: %s", err, string(output))
			}
		} else {
			// 尝试使用英文接口名
			output, err = runCmdCombined("netsh", "interface", "ipv4", "set", "dnsservers",
				"Ethernet", "static", dnsServers[0], "primary")
			if err != nil {
				log.Printf("警告: 设置主DNS失败: %v, 输出: %s", err, string(output))
			}
		}
	}

	// 添加备用 DNS
	for i := 1; i < len(dnsServers); i++ {
		output, err = runCmdCombined("netsh", "interface", "ipv4", "add", "dnsservers",
			ifaceName, dnsServers[i], fmt.Sprintf("index=%d", i+1))
		if err != nil {
			// 尝试备选命令
			output, err = runCmdCombined("netsh", "interface", "ip", "add", "dns",
				ifaceName, dnsServers[i], fmt.Sprintf("index=%d", i+1))
			if err != nil {
				log.Printf("警告: 添加备用DNS %s失败: %v", dnsServers[i], err)
			}
		}
	}

	log.Printf("已设置DNS服务器: %v (接口: %s)", dnsServers, ifaceName)
	return nil
}

// RestoreDNS 恢复原始DNS配置（Windows版本）
func (rm *RouteManager) RestoreDNS() error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	// 尝试从备份文件读取
	backupPath := filepath.Join(os.TempDir(), "vpn_dns_backup.txt")
	if data, err := os.ReadFile(backupPath); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if isIPv4(line) {
				rm.originalDNS = append(rm.originalDNS, line)
			}
		}
	}

	if len(rm.originalDNS) == 0 {
		// 如果没有备份，设置为自动获取
		ifaceName := rm.defaultIface
		if ifaceName == "" {
			ifaceName = "以太网"
		}

		output, err := runCmdCombined("netsh", "interface", "ipv4", "set", "dnsservers",
			ifaceName, "dhcp")
		if err != nil {
			log.Printf("警告: 恢复DHCP DNS失败: %v, 输出: %s", err, string(output))
		} else {
			log.Println("已恢复DNS为DHCP自动获取")
		}
		return nil
	}

	// 恢复原始 DNS
	ifaceName := rm.defaultIface
	if ifaceName == "" {
		ifaceName = "以太网"
	}

	// 设置主 DNS
	if len(rm.originalDNS) > 0 {
		output, err := runCmdCombined("netsh", "interface", "ipv4", "set", "dnsservers",
			ifaceName, "static", rm.originalDNS[0], "primary")
		if err != nil {
			log.Printf("警告: 恢复主DNS失败: %v, 输出: %s", err, string(output))
		}
	}

	// 添加备用 DNS
	for i := 1; i < len(rm.originalDNS); i++ {
		_, err := runCmdCombined("netsh", "interface", "ipv4", "add", "dnsservers",
			ifaceName, rm.originalDNS[i], fmt.Sprintf("index=%d", i+1))
		if err != nil {
			log.Printf("警告: 恢复备用DNS失败: %v", err)
		}
	}

	// 删除备份文件
	os.Remove(backupPath)

	log.Printf("已恢复原始DNS配置: %v", rm.originalDNS)
	return nil
}

// parseCIDR 解析 CIDR 格式为 IP 和子网掩码
func parseCIDR(cidr string) (string, string) {
	parts := strings.Split(cidr, "/")
	if len(parts) != 2 {
		// 如果不是 CIDR 格式，假设是单个 IP
		return cidr, "255.255.255.255"
	}

	ip := parts[0]
	mask := cidrToNetmask(parts[1])
	return ip, mask
}

// splitLines 辅助函数：分割字符串为行
func splitLines(s string) []string {
	lines := make([]string, 0)
	current := ""
	for _, ch := range s {
		if ch == '\n' {
			lines = append(lines, current)
			current = ""
		} else {
			current += string(ch)
		}
	}
	if current != "" {
		lines = append(lines, current)
	}
	return lines
}

// trimSpace 辅助函数：去除首尾空格
func trimSpace(s string) string {
	return strings.TrimSpace(s)
}

// splitBySpace 辅助函数：按空格分割字符串
func splitBySpace(s string) []string {
	return strings.Fields(s)
}

// getInterfaceIndexByNameOrIP 获取接口索引（通过名称或IP地址）
func getInterfaceIndexByNameOrIP(nameOrIP string) (int, error) {
	// 首先尝试按IP地址查找
	if isIPv4(nameOrIP) {
		idx, err := getInterfaceIndexByIP(nameOrIP)
		if err == nil {
			return idx, nil
		}
		log.Printf("通过IP地址查找接口失败: %v，尝试其他方法", err)
	}
	
	// 然后尝试按名称查找
	idx, err := getInterfaceIndex(nameOrIP)
	if err == nil {
		return idx, nil
	}
	
	return 0, fmt.Errorf("无法找到接口 %s", nameOrIP)
}

// getInterfaceIndexByIP 通过IP地址获取接口索引
func getInterfaceIndexByIP(ipAddr string) (int, error) {
	// 使用 netsh interface ipv4 show config 获取详细信息
	output, err := exec.Command("netsh", "interface", "ipv4", "show", "config").Output()
	if err != nil {
		return 0, fmt.Errorf("执行netsh命令失败: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	var currentIfName string
	
	for i, line := range lines {
		line = strings.TrimSpace(line)
		
		// 查找接口配置行，例如: "配置接口 "本地连接 2""
		if strings.Contains(line, "配置") && strings.Contains(line, "\"") ||
		   strings.Contains(line, "Configuration") && strings.Contains(line, "\"") {
			// 提取接口名称
			start := strings.Index(line, "\"")
			if start >= 0 {
				end := strings.Index(line[start+1:], "\"")
				if end >= 0 {
					currentIfName = line[start+1 : start+1+end]
				}
			}
		}
		
		// 查找IP地址匹配
		if strings.Contains(line, "IP") && strings.Contains(line, ipAddr) {
			// 找到了匹配的IP，获取这个接口的索引
			if currentIfName != "" {
				return getInterfaceIndexByName(currentIfName)
			}
		}
		
		// 另一种格式检查
		if strings.Contains(line, ipAddr) && i > 0 {
			// 回溯查找接口名
			for j := i - 1; j >= 0 && j >= i-10; j-- {
				prevLine := strings.TrimSpace(lines[j])
				if strings.Contains(prevLine, "配置") && strings.Contains(prevLine, "\"") ||
				   strings.Contains(prevLine, "Configuration") && strings.Contains(prevLine, "\"") {
					start := strings.Index(prevLine, "\"")
					if start >= 0 {
						end := strings.Index(prevLine[start+1:], "\"")
						if end >= 0 {
							ifName := prevLine[start+1 : start+1+end]
							return getInterfaceIndexByName(ifName)
						}
					}
				}
			}
		}
	}

	return 0, fmt.Errorf("未找到IP地址 %s 对应的接口", ipAddr)
}

// getInterfaceIndexByName 通过接口名称获取索引
func getInterfaceIndexByName(name string) (int, error) {
	output, err := exec.Command("netsh", "interface", "ipv4", "show", "interfaces").Output()
	if err != nil {
		return 0, fmt.Errorf("获取接口列表失败: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// 检查这行是否包含我们要找的接口名
		if strings.Contains(line, name) {
			// 解析接口索引（第一列）
			fields := strings.Fields(line)
			if len(fields) >= 1 {
				var idx int
				if _, err := fmt.Sscanf(fields[0], "%d", &idx); err == nil && idx > 0 {
					return idx, nil
				}
			}
		}
	}

	return 0, fmt.Errorf("未找到接口名称: %s", name)
}
