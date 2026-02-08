package main

import (
	"fmt"
	"log"
	"os/exec"
)

// SetupNAT 配置NAT并跟踪规则（VPNServer方法）
func (s *VPNServer) SetupNAT(vpnNetwork string, outInterface string) error {
	args := []string{"-s", vpnNetwork, "-o", outInterface, "-j", "MASQUERADE"}

	// 检查规则是否已存在
	checkArgs := append([]string{"-t", "nat", "-C", "POSTROUTING"}, args...)
	if runCmdSilent("iptables", checkArgs...) == nil {
		log.Println("NAT规则已存在，跳过添加")
		return nil
	}

	// 添加规则
	addArgs := append([]string{"-t", "nat", "-A", "POSTROUTING"}, args...)
	output, err := runCmdCombined("iptables", addArgs...)
	if err != nil {
		return fmt.Errorf("添加NAT规则失败: %v, 输出: %s", err, string(output))
	}

	// 记录规则以便后续清理
	s.natRules = append(s.natRules, NATRule{
		Table: "nat",
		Chain: "POSTROUTING",
		Args:  args,
	})

	log.Printf("已配置NAT: %s -> %s", vpnNetwork, outInterface)
	return nil
}

// setupServerNAT 配置服务器NAT（辅助函数）
func setupServerNAT(server *VPNServer, config VPNConfig) error {
	// 确定NAT出口接口
	natIface := config.NATInterface
	if natIface == "" {
		// 自动检测默认出口接口
		cmd := exec.Command("ip", "route", "show", "default")
		output, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("检测默认出口接口失败: %v", err)
		}

		// 解析输出
		lines := string(output)
		parts := splitBySpace(lines)
		for i := 0; i < len(parts); i++ {
			if parts[i] == "dev" && i+1 < len(parts) {
				natIface = parts[i+1]
				break
			}
		}

		if natIface == "" {
			return fmt.Errorf("无法自动检测出口接口")
		}
		log.Printf("自动检测到NAT出口接口: %s", natIface)
	}

	// 配置NAT
	if err := server.SetupNAT(config.Network, natIface); err != nil {
		return fmt.Errorf("配置NAT失败: %v", err)
	}

	// 获取实际的TUN设备名称
	tunDeviceName := server.tunDevice.Name()

	// 添加FORWARD规则
	// 允许 tun -> natIface 的转发
	forwardArgs1 := []string{"-A", "FORWARD", "-i", tunDeviceName, "-o", natIface, "-j", "ACCEPT"}
	cmd := exec.Command("iptables", forwardArgs1...)
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("警告：添加FORWARD规则失败: %v, 输出: %s", err, string(output))
	} else {
		log.Printf("已添加FORWARD规则: %s -> %s", tunDeviceName, natIface)
		// 记录规则以便清理
		server.natRules = append(server.natRules, NATRule{
			Table: "filter",
			Chain: "FORWARD",
			Args:  []string{"-i", tunDeviceName, "-o", natIface, "-j", "ACCEPT"},
		})
	}

	// 允许 natIface -> tun 的已建立连接
	forwardArgs2 := []string{"-A", "FORWARD", "-i", natIface, "-o", tunDeviceName, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"}
	cmd = exec.Command("iptables", forwardArgs2...)
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("警告：添加FORWARD规则失败: %v, 输出: %s", err, string(output))
	} else {
		log.Printf("已添加FORWARD规则: %s -> %s (RELATED,ESTABLISHED)", natIface, tunDeviceName)
		// 记录规则以便清理
		server.natRules = append(server.natRules, NATRule{
			Table: "filter",
			Chain: "FORWARD",
			Args:  []string{"-i", natIface, "-o", tunDeviceName, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
		})
	}

	return nil
}

// NATRule NAT规则记录
type NATRule struct {
	Table string   // "nat"
	Chain string   // "POSTROUTING"
	Args  []string // 规则参数
}
