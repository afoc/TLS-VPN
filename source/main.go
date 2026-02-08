package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-h", "--help", "help":
			printHelp()
			return

		case "--service":
			// 后台服务模式（daemon）
			runServiceDaemon()
			return

		case "--stop":
			// 停止服务
			stopService()
			return

		case "--status":
			// 显示服务状态
			showStatus()
			return

		default:
			fmt.Printf("未知参数: %s\n", os.Args[1])
			fmt.Println("使用 --help 查看帮助")
			return
		}
	}

	// 默认：智能启动（自动启动 daemon + TUI）
	runSmart()
}

func printHelp() {
	fmt.Println("╔══════════════════════════════════════════════════╗")
	fmt.Println("║           TLS VPN 管理系统                        ║")
	fmt.Println("╚══════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("用法:")
	fmt.Println("  ./tls-vpn              启动管理界面（推荐）")
	fmt.Println("  ./tls-vpn --service    仅启动后台服务（无界面）")
	fmt.Println("  ./tls-vpn --status     查看服务状态")
	fmt.Println("  ./tls-vpn --stop       停止后台服务")
	fmt.Println()
	fmt.Println("工作方式:")
	fmt.Println("  1. 运行 ./tls-vpn 会自动在后台启动服务")
	fmt.Println("  2. TUI 界面通过 IPC 连接后台服务")
	fmt.Println("  3. 退出 TUI 后，服务继续在后台运行")
	fmt.Println("  4. 再次运行 ./tls-vpn 可重新进入管理界面")
	fmt.Println()
	fmt.Printf("日志文件: %s\n", DefaultLogPath)
	fmt.Println("控制套接字: /var/run/vpn_control.sock")
}

// runSmart 智能启动：自动确保 daemon 运行，然后启动 TUI
func runSmart() {
	client := NewControlClient()

	// 检查服务是否已运行
	if !client.IsServiceRunning() {
		fmt.Println("正在启动后台服务...")

		// Fork daemon 进程
		if err := startDaemon(); err != nil {
			fmt.Printf("启动后台服务失败: %v\n", err)
			fmt.Println()
			fmt.Println("请尝试手动启动:")
			fmt.Println("  sudo ./tls-vpn --service &")
			return
		}

		// 等待 daemon 就绪
		if !waitForService(client, 5*time.Second) {
			fmt.Println("后台服务启动超时")
			fmt.Println()
			fmt.Printf("请检查日志: %s\n", DefaultLogPath)
			return
		}

		fmt.Println("后台服务已就绪")
	} else {
		fmt.Println("检测到服务已运行，连接中...")
	}

	// 启动 TUI（IPC 模式）
	runTUI(client)
}

// startDaemon 在 daemon_unix.go 和 daemon_windows.go 中定义

// waitForService 等待服务就绪
func waitForService(client *ControlClient, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		if client.IsServiceRunning() {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}

	return false
}

// runTUI 运行 TUI 界面（IPC 模式）
func runTUI(client *ControlClient) {
	sigChan := setupSignalHandler()

	app := NewTUIApp(client)

	go func() {
		<-sigChan
		app.Stop()
	}()

	if err := app.Run(); err != nil {
		fmt.Printf("TUI 错误: %v\n", err)
		os.Exit(1)
	}
}

// runServiceDaemon 运行后台服务（daemon 模式）
func runServiceDaemon() {
	// 设置日志
	logWriter, err := NewRotatingFileWriter(DefaultLogPath, 10, 5)
	if err != nil {
		log.Printf("警告: 无法打开日志文件: %v, 使用标准输出", err)
		logWriter = nil
	} else {
		defer logWriter.Close()
	}

	logger := InitServiceLogger(logWriter)
	log.SetOutput(logger)
	log.SetFlags(log.Ldate | log.Ltime)

	log.Println("========================================")
	log.Printf("TLS VPN 服务启动 (PID: %d)", os.Getpid())
	log.Println("========================================")

	// 创建服务
	service := NewVPNService()

	// 创建控制服务器
	controlServer := NewControlServer(service)
	if err := controlServer.Start(); err != nil {
		log.Fatalf("启动控制服务器失败: %v", err)
	}

	// 只在终端模式下打印（daemon 模式下不会有终端）
	if isTerminal() {
		fmt.Println("TLS VPN 服务已启动")
		fmt.Println("控制套接字:", ControlSocketPath)
		fmt.Println()
		fmt.Println("使用 ./tls-vpn 进入管理界面")
		fmt.Println("使用 ./tls-vpn --stop 停止服务")
	}

	// 等待退出信号
	sigChan := setupSignalHandler()

	<-sigChan
	log.Println("收到退出信号，正在停止服务...")

	service.Cleanup()
	controlServer.Stop()

	log.Println("TLS VPN 服务已退出")
}

// isTerminal 检查是否在终端中运行
func isTerminal() bool {
	fileInfo, _ := os.Stdout.Stat()
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}

// stopService 停止服务
func stopService() {
	client := NewControlClient()
	if !client.IsServiceRunning() {
		fmt.Println("服务未运行")
		return
	}

	fmt.Println("正在停止服务...")
	resp, err := client.Shutdown()
	if err != nil {
		fmt.Printf("停止失败: %v\n", err)
		return
	}
	if resp.Success {
		fmt.Println("服务已停止")
	} else {
		fmt.Printf("停止失败: %s\n", resp.Error)
	}
}

// showStatus 显示服务状态
func showStatus() {
	client := NewControlClient()
	if !client.IsServiceRunning() {
		fmt.Println("服务状态: [未运行]")
		fmt.Println()
		fmt.Println("启动: ./tls-vpn")
		return
	}

	fmt.Println("服务状态: [运行中]")
	fmt.Println()

	serverStatus, err := client.ServerStatus()
	if err == nil {
		if serverStatus.Running {
			fmt.Printf("VPN服务端: 运行中 (端口: %d, 客户端: %d)\n",
				serverStatus.Port, serverStatus.ClientCount)
			fmt.Printf("  TUN设备: %s\n", serverStatus.TUNDevice)
			fmt.Printf("  网段: %s\n", serverStatus.Network)
			fmt.Printf("  流量: ↑%s ↓%s\n",
				formatBytes(serverStatus.TotalSent), formatBytes(serverStatus.TotalRecv))
		} else {
			fmt.Println("VPN服务端: 未启动")
		}
	}

	clientStatus, err := client.ClientStatus()
	if err == nil {
		if clientStatus.Connected {
			fmt.Printf("VPN客户端: 已连接 (IP: %s)\n", clientStatus.AssignedIP)
			fmt.Printf("  服务器: %s:%d\n", clientStatus.ServerAddress, clientStatus.ServerPort)
		} else {
			fmt.Println("VPN客户端: 未连接")
		}
	}

	cfg, err := client.ConfigGet()
	if err == nil {
		fmt.Println()
		fmt.Println("当前配置:")
		cfgJSON, _ := json.MarshalIndent(cfg, "  ", "  ")
		fmt.Printf("  %s\n", string(cfgJSON))
	}
}
