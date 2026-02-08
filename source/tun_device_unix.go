//go:build !windows
// +build !windows

package main

import (
	"fmt"
	"log"
	"os/exec"

	"github.com/songgao/water"
)

// createTUNDevice 创建TUN设备（Unix/Linux版本）
func createTUNDevice(baseName string, network string) (TUNDevice, error) {
	config := water.Config{
		DeviceType: water.TUN,
	}

	// Linux可以指定设备名称
	if baseName != "" {
		config.Name = baseName
	}

	iface, err := water.New(config)
	if err != nil {
		return nil, fmt.Errorf("创建TUN设备失败: %v", err)
	}

	log.Printf("成功创建TUN设备: %s", iface.Name())
	
	// water.Interface自动实现TUNDevice接口
	return iface, nil
}

// configureTUNDevice 配置TUN设备（Unix/Linux版本）
func configureTUNDevice(ifaceName string, ipAddr string, mtu int) error {
	// 配置IP地址
	output, err := exec.Command("ip", "addr", "add", ipAddr, "dev", ifaceName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("设置IP地址失败: %v, 输出: %s", err, string(output))
	}

	// 设置MTU
	output, err = exec.Command("ip", "link", "set", "dev", ifaceName, "mtu", fmt.Sprintf("%d", mtu)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("设置MTU失败: %v, 输出: %s", err, string(output))
	}

	// 启动设备
	output, err = exec.Command("ip", "link", "set", "dev", ifaceName, "up").CombinedOutput()
	if err != nil {
		return fmt.Errorf("启动设备失败: %v, 输出: %s", err, string(output))
	}

	log.Printf("配置TUN设备完成: %s IP=%s MTU=%d", ifaceName, ipAddr, mtu)
	return nil
}

// cleanupTUNDevice 清理TUN设备（Unix/Linux版本）
func cleanupTUNDevice(ifaceName string) {
	log.Printf("清理TUN设备: %s", ifaceName)
	// 关闭设备
	_ = exec.Command("ip", "link", "set", "dev", ifaceName, "down").Run()
	// 删除设备（TUN设备会在close时自动删除）
}

// checkRootPrivileges 检查root权限（Unix/Linux版本）
func checkRootPrivileges() error {
	output, err := exec.Command("id", "-u").Output()
	if err != nil {
		return fmt.Errorf("检查权限失败: %v", err)
	}

	uid := string(output)
	if uid[0] != '0' {
		return fmt.Errorf("需要root权限运行，请使用: sudo %s", "tls-vpn")
	}

	return nil
}

// enableIPForwarding 启用IP转发（Unix/Linux版本）
func enableIPForwarding() error {
	output, err := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").CombinedOutput()
	if err != nil {
		return fmt.Errorf("启用IP转发失败: %v, 输出: %s", err, string(output))
	}

	log.Println("已启用IP转发")
	return nil
}
