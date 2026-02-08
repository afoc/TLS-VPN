package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// ================ 服务端处理 ================

func handleServerStart(t *TUIApp) {
	t.addLog("正在启动服务端...")
	go func() {
		resp, err := t.client.ServerStart()
		if err != nil {
			t.addLog("[red]启动失败: %v", err)
			return
		}
		if resp.Success {
			t.addLog("[green]%s", resp.Message)
		} else {
			t.addLog("[red]%s", resp.Error)
		}
	}()
}

func handleServerStop(t *TUIApp) {
	t.addLog("正在停止服务端...")
	go func() {
		resp, err := t.client.ServerStop()
		if err != nil {
			t.addLog("[red]停止失败: %v", err)
			return
		}
		if resp.Success {
			t.addLog("[green]%s", resp.Message)
		} else {
			t.addLog("[red]%s", resp.Error)
		}
	}()
}

func handleShowClients(t *TUIApp) {
	clients, err := t.client.ServerClients()
	if err != nil {
		t.showInfoDialog("在线客户端", "获取失败: "+err.Error())
		return
	}

	if len(clients) == 0 {
		t.showInfoDialog("在线客户端", "当前没有客户端连接")
		return
	}

	var content strings.Builder
	content.WriteString(fmt.Sprintf("在线客户端数量: [green]%d[white]\n\n", len(clients)))
	content.WriteString("┌────┬──────────────┬──────────────┬──────────────┬──────────┐\n")
	content.WriteString("│ #  │ IP地址       │ 发送流量     │ 接收流量     │ 连接时间 │\n")
	content.WriteString("├────┼──────────────┼──────────────┼──────────────┼──────────┤\n")

	for i, c := range clients {
		content.WriteString(fmt.Sprintf("│ %2d │ %-12s │ %12s │ %12s │ %8s │\n",
			i+1, c.IP, formatBytes(c.BytesSent), formatBytes(c.BytesReceived), c.Duration))
	}
	content.WriteString("└────┴──────────────┴──────────────┴──────────────┴──────────┘")

	t.showInfoDialog("在线客户端", content.String())
}

func handleKickClient(t *TUIApp) {
	clients, err := t.client.ServerClients()
	if err != nil {
		t.addLog("[red]获取客户端列表失败: %v", err)
		return
	}
	if len(clients) == 0 {
		t.addLog("[yellow]当前没有客户端连接")
		return
	}

	defaultIP := clients[0].IP
	t.showInputDialog("输入要踢出的客户端IP", defaultIP, func(ip string) {
		if ip == "" {
			return
		}
		resp, err := t.client.ServerKick(ip)
		if err != nil {
			t.addLog("[red]踢出失败: %v", err)
		} else if resp.Success {
			t.addLog("[green]%s", resp.Message)
		} else {
			t.addLog("[red]%s", resp.Error)
		}
	})
}

func handleShowStats(t *TUIApp) {
	status, err := t.client.ServerStatus()
	if err != nil {
		t.showInfoDialog("流量统计", "获取失败: "+err.Error())
		return
	}

	if !status.Running {
		t.showInfoDialog("流量统计", "服务端未运行")
		return
	}

	clients, _ := t.client.ServerClients()

	var content strings.Builder
	content.WriteString(fmt.Sprintf("总发送流量: [green]%s[white]\n", formatBytes(status.TotalSent)))
	content.WriteString(fmt.Sprintf("总接收流量: [green]%s[white]\n", formatBytes(status.TotalRecv)))
	content.WriteString(fmt.Sprintf("在线客户端: [green]%d[white]\n\n", len(clients)))

	if len(clients) > 0 {
		content.WriteString("客户端流量详情:\n")
		for _, c := range clients {
			content.WriteString(fmt.Sprintf("  %s: ↑%s ↓%s\n",
				c.IP, formatBytes(c.BytesSent), formatBytes(c.BytesReceived)))
		}
	}

	t.showInfoDialog("流量统计", content.String())
}

// ================ 服务端设置处理 ================

func handleSetPort(t *TUIApp) {
	cfg, _ := t.client.ConfigGet()
	t.showInputDialog("监听端口", fmt.Sprintf("%d", cfg.ServerPort), func(value string) {
		if port, err := strconv.Atoi(value); err == nil && port > 0 && port < 65536 {
			resp, _ := t.client.ConfigUpdate("server_port", float64(port))
			if resp != nil && resp.Success {
				t.addLog("[green]端口已设置为: %d", port)
			} else {
				t.addLog("[red]设置失败")
			}
		} else {
			t.addLog("[red]无效的端口号")
		}
		t.showMenu("server_settings")
	})
}

func handleSetNetwork(t *TUIApp) {
	cfg, _ := t.client.ConfigGet()
	t.showInputDialog("VPN网段", cfg.Network, func(value string) {
		resp, _ := t.client.ConfigUpdate("network", value)
		if resp != nil && resp.Success {
			t.addLog("[green]VPN网段已设置为: %s", value)
		} else {
			t.addLog("[red]设置失败")
		}
		t.showMenu("server_settings")
	})
}

func handleSetMTU(t *TUIApp) {
	cfg, _ := t.client.ConfigGet()
	t.showInputDialog("MTU", fmt.Sprintf("%d", cfg.MTU), func(value string) {
		if mtu, err := strconv.Atoi(value); err == nil && mtu >= 576 && mtu <= 9000 {
			resp, _ := t.client.ConfigUpdate("mtu", float64(mtu))
			if resp != nil && resp.Success {
				t.addLog("[green]MTU已设置为: %d", mtu)
			} else {
				t.addLog("[red]设置失败")
			}
		} else {
			t.addLog("[red]MTU必须在576-9000之间")
		}
		t.showMenu("server_settings")
	})
}

func handleSetNATInterface(t *TUIApp) {
	cfg, _ := t.client.ConfigGet()
	t.showInputDialog("NAT出口网卡 (空=自动)", cfg.NATInterface, func(value string) {
		resp, _ := t.client.ConfigUpdate("nat_interface", value)
		if resp != nil && resp.Success {
			if value == "" {
				t.addLog("[green]将自动检测NAT出口网卡")
			} else {
				t.addLog("[green]NAT出口网卡已设置为: %s", value)
			}
		}
		t.showMenu("server_settings")
	})
}

func handleSetMaxConnections(t *TUIApp) {
	cfg, _ := t.client.ConfigGet()
	t.showInputDialog("最大连接数", fmt.Sprintf("%d", cfg.MaxConnections), func(value string) {
		if max, err := strconv.Atoi(value); err == nil && max > 0 && max <= 10000 {
			resp, _ := t.client.ConfigUpdate("max_connections", float64(max))
			if resp != nil && resp.Success {
				t.addLog("[green]最大连接数已设置为: %d", max)
			}
		} else {
			t.addLog("[red]无效的连接数")
		}
		t.showMenu("server_settings")
	})
}

func handleSetRouteModeFull(t *TUIApp) {
	t.client.ConfigUpdate("route_mode", "full")
	t.client.ConfigUpdate("enable_nat", true)
	t.client.ConfigUpdate("redirect_gateway", true)
	t.addLog("[green]已设置为NAT模式")
	t.showMenu("route_mode")
}

func handleSetRouteModeSplit(t *TUIApp) {
	t.client.ConfigUpdate("route_mode", "split")
	t.client.ConfigUpdate("enable_nat", true)
	t.client.ConfigUpdate("redirect_gateway", false)
	t.addLog("[green]已设置为分流模式")
	t.showMenu("route_mode")
}

func handleToggleNAT(t *TUIApp) {
	cfg, _ := t.client.ConfigGet()
	newValue := !cfg.EnableNAT
	t.client.ConfigUpdate("enable_nat", newValue)
	if newValue {
		t.addLog("[green]NAT已启用")
	} else {
		t.addLog("[yellow]NAT已禁用")
	}
	t.showMenu("route_mode")
}

func handleShowPushRoutes(t *TUIApp) {
	cfg, _ := t.client.ConfigGet()
	if len(cfg.PushRoutes) == 0 {
		t.showInfoDialog("推送路由", "暂无推送路由")
		return
	}
	var content strings.Builder
	content.WriteString("当前推送路由:\n\n")
	for i, route := range cfg.PushRoutes {
		content.WriteString(fmt.Sprintf("  %d. %s\n", i+1, route))
	}
	t.showInfoDialog("推送路由", content.String())
}

func handleAddPushRoute(t *TUIApp) {
	t.showInputDialog("输入网段 (如 192.168.1.0/24)", "", func(value string) {
		if value == "" {
			return
		}
		cfg, _ := t.client.ConfigGet()
		routes := append(cfg.PushRoutes, value)
		interfaceRoutes := make([]interface{}, len(routes))
		for i, r := range routes {
			interfaceRoutes[i] = r
		}
		resp, _ := t.client.ConfigUpdate("push_routes", interfaceRoutes)
		if resp != nil && resp.Success {
			t.addLog("[green]已添加路由: %s", value)
		} else {
			t.addLog("[red]添加失败")
		}
		t.showMenu("push_routes")
	})
}

func handleClearPushRoutes(t *TUIApp) {
	t.showConfirmDialog("确定清空所有推送路由?", func(confirmed bool) {
		if confirmed {
			t.client.ConfigUpdate("push_routes", []interface{}{})
			t.addLog("[green]已清空所有推送路由")
		}
		t.showMenu("push_routes")
	})
}

// ================ DNS设置处理 ================

func handleToggleDNS(t *TUIApp) {
	cfg, _ := t.client.ConfigGet()
	newValue := !cfg.RedirectDNS
	t.client.ConfigUpdate("redirect_dns", newValue)
	if newValue {
		t.addLog("[green]DNS劫持已启用 - 客户端将使用服务端推送的DNS")
	} else {
		t.addLog("[yellow]DNS劫持已禁用 - 客户端将使用本地DNS")
	}
	t.showMenu("dns_settings")
}

func handleSetDNSServers(t *TUIApp) {
	cfg, _ := t.client.ConfigGet()
	currentDNS := ""
	if len(cfg.DNSServers) > 0 {
		for i, dns := range cfg.DNSServers {
			if i > 0 {
				currentDNS += ","
			}
			currentDNS += dns
		}
	}
	t.showInputDialog("DNS服务器 (多个用逗号分隔，如 8.8.8.8,8.8.4.4)", currentDNS, func(value string) {
		if value == "" {
			t.addLog("[yellow]DNS服务器不能为空")
			t.showMenu("dns_settings")
			return
		}
		// 解析DNS服务器列表
		dnsServers := []interface{}{}
		for _, dns := range splitByComma(value) {
			dns = trimSpace(dns)
			if dns != "" {
				// 简单验证IP格式
				if net.ParseIP(dns) != nil {
					dnsServers = append(dnsServers, dns)
				} else {
					t.addLog("[red]无效的DNS服务器地址: %s", dns)
					t.showMenu("dns_settings")
					return
				}
			}
		}
		if len(dnsServers) == 0 {
			t.addLog("[yellow]至少需要一个有效的DNS服务器")
			t.showMenu("dns_settings")
			return
		}
		resp, _ := t.client.ConfigUpdate("dns_servers", dnsServers)
		if resp != nil && resp.Success {
			t.addLog("[green]DNS服务器已设置为: %v", dnsServers)
		} else {
			t.addLog("[red]设置DNS服务器失败")
		}
		t.showMenu("dns_settings")
	})
}

func handleShowDNSConfig(t *TUIApp) {
	cfg, _ := t.client.ConfigGet()
	var content strings.Builder
	content.WriteString("当前DNS配置:\n\n")

	// DNS劫持状态
	if cfg.RedirectDNS {
		content.WriteString("  DNS劫持:    [green]已启用[white]\n")
	} else {
		content.WriteString("  DNS劫持:    [yellow]已禁用[white]\n")
	}

	// DNS服务器列表
	content.WriteString("\n  DNS服务器:\n")
	if len(cfg.DNSServers) == 0 {
		content.WriteString("    (未配置)\n")
	} else {
		for i, dns := range cfg.DNSServers {
			content.WriteString(fmt.Sprintf("    %d. %s\n", i+1, dns))
		}
	}

	content.WriteString("\n说明:\n")
	content.WriteString("  · 启用DNS劫持后，客户端连接VPN时会自动使用上述DNS服务器\n")
	content.WriteString("  · 断开VPN后，客户端会恢复原有DNS配置\n")

	t.showInfoDialog("DNS配置", content.String())
}

// splitByComma 按逗号分割字符串
func splitByComma(s string) []string {
	result := []string{}
	current := ""
	for _, c := range s {
		if c == ',' {
			result = append(result, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

// ================ 证书处理 ================

func handleInitCA(t *TUIApp) {
	t.showConfirmDialog("确定初始化CA? (会覆盖现有证书)", func(confirmed bool) {
		if !confirmed {
			return
		}
		t.addLog("正在生成CA证书...")
		go func() {
			resp, err := t.client.CertInitCA()
			if err != nil {
				t.addLog("[red]生成失败: %v", err)
			} else if resp.Success {
				t.addLog("[green]CA证书已生成")
			} else {
				t.addLog("[red]%s", resp.Error)
			}
		}()
	})
}

func handleShowCertList(t *TUIApp) {
	list, err := t.client.CertList()
	if err != nil {
		t.showInfoDialog("证书列表", "获取失败: "+err.Error())
		return
	}

	var content strings.Builder
	content.WriteString(fmt.Sprintf("证书目录: %s\n\n", list.CertDir))

	for _, f := range list.Files {
		if f.Exists {
			content.WriteString(fmt.Sprintf("[green]✓[white] %-20s %10d bytes  %s\n",
				f.Name, f.Size, f.Modified.Format("2006-01-02 15:04")))
		} else {
			content.WriteString(fmt.Sprintf("[red]✗[white] %-20s (不存在)\n", f.Name))
		}
	}

	t.showInfoDialog("证书列表", content.String())
}

func handleShowSignedClients(t *TUIApp) {
	resp, err := t.client.Call(ActionCertClients, nil)
	if err != nil {
		t.showInfoDialog("已签发客户端", "获取失败: "+err.Error())
		return
	}

	var result SignedClientsResponse
	if resp.Data != nil {
		parseJSON(resp.Data, &result)
	}

	if len(result.Clients) == 0 {
		t.showInfoDialog("已签发客户端证书", "(暂无已签发的客户端证书)")
		return
	}

	var content strings.Builder
	content.WriteString("客户端证书列表:\n\n")
	for i, c := range result.Clients {
		content.WriteString(fmt.Sprintf("%d. %-30s %s\n", i+1, c.Name, c.Modified.Format("2006-01-02 15:04")))
	}

	t.showInfoDialog("已签发客户端证书", content.String())
}

// ================ Token 处理 ================

func handleGenToken(t *TUIApp) {
	t.showInputDialog("客户端名称", "", func(clientName string) {
		if clientName == "" {
			t.addLog("[red]客户端名称不能为空")
			return
		}
		t.showInputDialog("有效期(小时)", "24", func(durationStr string) {
			duration, _ := strconv.Atoi(durationStr)
			if duration <= 0 {
				duration = 24
			}

			go func() {
				token, err := t.client.TokenGenerate(clientName, duration)
				if err != nil {
					t.addLog("[red]生成Token失败: %v", err)
					return
				}

				t.addLog("[green]========== Token生成成功 ==========")
				t.addLog("Token ID:  %s", token.TokenID)
				t.addLog("Token Key: %s", token.TokenKey)
				t.addLog("")
				t.addLog("[cyan]完整Token (可直接复制粘贴):")
				t.addLog("[yellow]%s:%s", token.TokenID, token.TokenKey)
				t.addLog("")
				t.addLog("客户端:    %s", token.ClientName)
				t.addLog("过期时间:  %s", token.ExpiresAt.Format("2006-01-02 15:04:05"))
				t.addLog("保存路径:  %s", token.FilePath)
				t.addLog("[green]===================================")
			}()
		})
	})
}

func handleShowTokenList(t *TUIApp) {
	tokens, err := t.client.TokenList()
	if err != nil {
		t.showInfoDialog("Token列表", "获取失败: "+err.Error())
		return
	}

	if len(tokens) == 0 {
		t.showInfoDialog("Token列表", "暂无Token")
		return
	}

	var content strings.Builder
	content.WriteString(fmt.Sprintf("Token数量: [green]%d[white]\n\n", len(tokens)))
	content.WriteString("┌────┬────────────────────────────┬────────────┬──────────┬──────────┐\n")
	content.WriteString("│ #  │ Token ID                   │ 客户端     │ 状态     │ 过期时间 │\n")
	content.WriteString("├────┼────────────────────────────┼────────────┼──────────┼──────────┤\n")

	for i, tk := range tokens {
		status := "[green]有效"
		if tk.Status == "used" {
			status = "[gray]已使用"
		} else if tk.Status == "expired" {
			status = "[red]已过期"
		}

		tokenID := tk.ID
		if len(tokenID) > 26 {
			tokenID = tokenID[:26]
		}
		clientName := tk.ClientName
		if len(clientName) > 10 {
			clientName = clientName[:10]
		}

		content.WriteString(fmt.Sprintf("│ %2d │ %-26s │ %-10s │ %-8s[white] │ %s │\n",
			i+1, tokenID, clientName, status, tk.ExpiresAt.Format("01-02 15:04")))
	}
	content.WriteString("└────┴────────────────────────────┴────────────┴──────────┴──────────┘")

	t.showInfoDialog("Token列表", content.String())
}

func handleDeleteToken(t *TUIApp) {
	tokens, _ := t.client.TokenList()
	if len(tokens) == 0 {
		t.addLog("[yellow]暂无Token可删除")
		return
	}

	var content strings.Builder
	for i, tk := range tokens {
		content.WriteString(fmt.Sprintf("%d. %s (%s)\n", i+1, tk.ID, tk.ClientName))
	}
	t.addLog("Token列表:\n%s", content.String())

	t.showInputDialog("输入要删除的序号", "1", func(idxStr string) {
		idx, err := strconv.Atoi(idxStr)
		if err != nil || idx < 1 || idx > len(tokens) {
			t.addLog("[red]无效的序号")
			return
		}
		resp, _ := t.client.TokenDelete(idx)
		if resp != nil && resp.Success {
			t.addLog("[green]Token已删除")
		} else {
			t.addLog("[red]删除失败")
		}
		t.showMenu("token")
	})
}

func handleCleanupTokens(t *TUIApp) {
	resp, err := t.client.TokenCleanup()
	if err != nil {
		t.addLog("[red]清理失败: %v", err)
	} else if resp.Success {
		t.addLog("[green]%s", resp.Message)
	}
	t.showMenu("token")
}

// ================ 客户端处理 ================

func handleClientConnect(t *TUIApp) {
	t.addLog("正在连接VPN服务器...")
	go func() {
		resp, err := t.client.ClientConnect()
		if err != nil {
			t.addLog("[red]连接失败: %v", err)
			return
		}
		if resp.Success {
			t.addLog("[green]%s", resp.Message)
		} else {
			t.addLog("[red]%s", resp.Error)
		}
	}()
}

func handleClientDisconnect(t *TUIApp) {
	t.addLog("正在断开VPN连接...")
	go func() {
		resp, err := t.client.ClientDisconnect()
		if err != nil {
			t.addLog("[red]断开失败: %v", err)
			return
		}
		if resp.Success {
			t.addLog("[green]%s", resp.Message)
		} else {
			t.addLog("[red]%s", resp.Error)
		}
	}()
}

func handleShowClientStatus(t *TUIApp) {
	status, err := t.client.ClientStatus()
	if err != nil {
		t.showInfoDialog("客户端状态", "获取失败: "+err.Error())
		return
	}

	var content strings.Builder
	if !status.Connected {
		content.WriteString("状态: [red]未连接[white]\n\n")
	} else {
		content.WriteString("状态: [green]已连接[white]\n\n")
		if status.AssignedIP != "" {
			content.WriteString(fmt.Sprintf("VPN IP: [green]%s[white]\n", status.AssignedIP))
		}
		if status.TUNDevice != "" {
			content.WriteString(fmt.Sprintf("TUN设备: %s\n", status.TUNDevice))
		}
	}
	content.WriteString(fmt.Sprintf("服务器: %s:%d\n", status.ServerAddress, status.ServerPort))

	t.showInfoDialog("客户端状态", content.String())
}

func handleSetServerAddress(t *TUIApp) {
	cfg, _ := t.client.ConfigGet()
	t.showInputDialog("服务器地址", cfg.ServerAddress, func(value string) {
		if value != "" {
			t.client.ConfigUpdate("server_address", value)
			t.addLog("[green]服务器地址已设置为: %s", value)
		}
		t.showMenu("client_settings")
	})
}

func handleSetServerPort(t *TUIApp) {
	cfg, _ := t.client.ConfigGet()
	t.showInputDialog("服务器端口", fmt.Sprintf("%d", cfg.ServerPort), func(value string) {
		if port, err := strconv.Atoi(value); err == nil && port > 0 && port < 65536 {
			t.client.ConfigUpdate("server_port", float64(port))
			t.addLog("[green]服务器端口已设置为: %d", port)
		} else {
			t.addLog("[red]无效的端口号")
		}
		t.showMenu("client_settings")
	})
}

func handleGenCSR(t *TUIApp) {
	t.showInputDialog("请输入客户端名称", "", func(clientName string) {
		if clientName == "" {
			t.addLog("[red]客户端名称不能为空")
			return
		}
		t.addLog("正在生成CSR...")
		go func() {
			resp, err := t.client.CertGenCSR(clientName)
			if err != nil {
				t.addLog("[red]生成CSR失败: %v", err)
				return
			}
			t.addLog("[green]========== CSR生成成功 ==========")
			t.addLog("私钥文件: %s", resp.KeyFile)
			t.addLog("CSR文件:  %s", resp.CSRFile)
			t.addLog("CN:       %s", resp.CN)
			t.addLog("[green]=================================")
		}()
	})
}

func handleRequestCert(t *TUIApp) {
	// 查找 CSR 文件
	files, _ := os.ReadDir(".")
	var csrFiles []string
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".csr") {
			csrFiles = append(csrFiles, f.Name())
		}
	}
	if len(csrFiles) == 0 {
		t.addLog("[yellow]未找到CSR文件，请先生成CSR")
		return
	}

	t.showInputDialog("CSR文件路径", csrFiles[0], func(csrFile string) {
		// 询问Token输入方式
		t.showYesNoDialog("使用Token文件还是手动输入Token (粘贴ID:KEY)?", func(useFile bool) {
			cfg, _ := t.client.ConfigGet()

			if useFile {
				// 方式1: 从文件读取Token
				tokenFiles, _ := os.ReadDir(DefaultTokenDir)
				var validTokens []string
				for _, f := range tokenFiles {
					if strings.HasSuffix(f.Name(), ".json") {
						validTokens = append(validTokens, f.Name())
					}
				}

				defaultToken := ""
				if len(validTokens) > 0 {
					defaultToken = validTokens[0]
					t.addLog("可用Token文件:")
					for i, tf := range validTokens {
						t.addLog("  %d. %s", i+1, tf)
					}
				}

				t.showInputDialog("Token文件名", defaultToken, func(tokenFile string) {
					req := RequestCertRequest{
						CSRFile:       csrFile,
						ServerAddress: cfg.ServerAddress,
						ServerPort:    8081,
					}
					if tokenFile != "" {
						req.TokenFile = DefaultTokenDir + "/" + tokenFile
					}

					submitCertRequest(t, req)
				})
			} else {
				// 方式2/3: 手动输入Token
				t.addLog("[cyan]提示: 可以粘贴完整Token (格式: ID:KEY) 或只输入ID")
				t.showInputDialog("输入Token ID 或 ID:KEY", "", func(input string) {
					input = strings.TrimSpace(input)
					if input == "" {
						t.addLog("[red]Token不能为空")
						return
					}

					// 检查是否包含冒号，支持 "ID:KEY" 格式
					if strings.Contains(input, ":") {
						parts := strings.Split(input, ":")
						if len(parts) != 2 {
							t.addLog("[red]Token格式错误，应为: ID:KEY")
							return
						}

						tokenID := strings.TrimSpace(parts[0])
						tokenKey := strings.TrimSpace(parts[1])

						if tokenID == "" || tokenKey == "" {
							t.addLog("[red]Token ID或Key不能为空")
							return
						}

						req := RequestCertRequest{
							CSRFile:       csrFile,
							TokenID:       tokenID,
							TokenKey:      tokenKey,
							ServerAddress: cfg.ServerAddress,
							ServerPort:    8081,
						}

						t.addLog("[green]已解析Token: ID=%s, Key=%s...", tokenID, tokenKey[:16])
						submitCertRequest(t, req)
					} else {
						// 只输入了ID，继续询问Key
						tokenID := input
						t.showInputDialog("输入Token Key (hex)", "", func(tokenKey string) {
							tokenKey = strings.TrimSpace(tokenKey)
							if tokenKey == "" {
								t.addLog("[red]Token Key不能为空")
								return
							}

							req := RequestCertRequest{
								CSRFile:       csrFile,
								TokenID:       tokenID,
								TokenKey:      tokenKey,
								ServerAddress: cfg.ServerAddress,
								ServerPort:    8081,
							}

							submitCertRequest(t, req)
						})
					}
				})
			}
		})
	})
}

// submitCertRequest 提交证书申请请求（辅助函数）
func submitCertRequest(t *TUIApp, req RequestCertRequest) {
	t.addLog("正在申请证书...")
	go func() {
		resp, err := t.client.CertRequest(req)
		if err != nil {
			t.addLog("[red]申请失败: %v", err)
			return
		}
		if resp.Success {
			t.addLog("[green]证书申请成功，已自动部署到 ./certs 目录")
		} else {
			t.addLog("[red]%s", resp.Error)
		}
	}()
}

func handleShowClientCertStatus(t *TUIApp) {
	list, err := t.client.CertList()
	if err != nil {
		t.showInfoDialog("本地证书状态", "获取失败: "+err.Error())
		return
	}

	var content strings.Builder
	content.WriteString(fmt.Sprintf("证书目录: %s\n\n", list.CertDir))

	certFiles := map[string]string{
		"ca.pem":         "CA证书 (服务端签发)",
		"client.pem":     "客户端证书",
		"client-key.pem": "客户端私钥",
	}

	for _, f := range list.Files {
		if desc, ok := certFiles[f.Name]; ok {
			if f.Exists {
				content.WriteString(fmt.Sprintf("[green]✓[white] %-20s %s\n", f.Name, desc))
				content.WriteString(fmt.Sprintf("    大小: %d bytes, 修改时间: %s\n", f.Size, f.Modified.Format("2006-01-02 15:04")))
			} else {
				content.WriteString(fmt.Sprintf("[red]✗[white] %-20s %s (不存在)\n", f.Name, desc))
			}
		}
	}

	t.showInfoDialog("本地证书状态", content.String())
}

// ================ 配置处理 ================

func handleSaveConfig(t *TUIApp) {
	resp, err := t.client.ConfigSave()
	if err != nil {
		t.addLog("[red]保存失败: %v", err)
	} else if resp.Success {
		t.addLog("[green]配置已保存")
	} else {
		t.addLog("[red]%s", resp.Error)
	}
}

func handleLoadConfig(t *TUIApp) {
	resp, err := t.client.ConfigLoad()
	if err != nil {
		t.addLog("[red]加载失败: %v", err)
	} else if resp.Success {
		t.addLog("[green]配置已加载")
		t.showMenu("config")
	} else {
		t.addLog("[red]%s", resp.Error)
	}
}

func handleShowConfig(t *TUIApp) {
	cfg, err := t.client.ConfigGet()
	if err != nil {
		t.showInfoDialog("当前配置", "获取失败: "+err.Error())
		return
	}

	var content strings.Builder
	content.WriteString("[yellow]网络配置:[white]\n")
	content.WriteString(fmt.Sprintf("  服务器地址:     %s\n", cfg.ServerAddress))
	content.WriteString(fmt.Sprintf("  服务器端口:     %d\n", cfg.ServerPort))
	content.WriteString(fmt.Sprintf("  VPN网段:        %s\n", cfg.Network))
	content.WriteString(fmt.Sprintf("  服务器IP:       %s\n", cfg.ServerIP))
	content.WriteString(fmt.Sprintf("  MTU:            %d\n", cfg.MTU))

	content.WriteString("\n[yellow]路由配置:[white]\n")
	content.WriteString(fmt.Sprintf("  路由模式:       %s\n", cfg.RouteMode))
	content.WriteString(fmt.Sprintf("  启用NAT:        %v\n", cfg.EnableNAT))
	content.WriteString(fmt.Sprintf("  NAT出口:        %s\n", cfg.NATInterface))
	content.WriteString(fmt.Sprintf("  重定向网关:     %v\n", cfg.RedirectGateway))
	content.WriteString(fmt.Sprintf("  DNS服务器:      %v\n", cfg.DNSServers))
	content.WriteString(fmt.Sprintf("  推送路由:       %v\n", cfg.PushRoutes))

	content.WriteString("\n[yellow]会话配置:[white]\n")
	content.WriteString(fmt.Sprintf("  最大连接数:     %d\n", cfg.MaxConnections))
	content.WriteString(fmt.Sprintf("  会话超时:       %v\n", cfg.SessionTimeout))
	content.WriteString(fmt.Sprintf("  心跳超时:       %v\n", cfg.KeepAliveTimeout))

	t.showInfoDialog("当前配置", content.String())
}

func handleResetConfig(t *TUIApp) {
	t.showConfirmDialog("确定恢复默认配置?", func(confirmed bool) {
		if confirmed {
			resp, _ := t.client.ConfigReset()
			if resp != nil && resp.Success {
				t.addLog("[green]已恢复默认配置")
			}
		}
	})
}

// ================ 向导处理 ================

func handleServerWizard(t *TUIApp) {
	t.addLog("开始服务端快速部署向导...")
	t.addLog("[cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	// 检查后台服务是否运行
	if !t.client.IsServiceRunning() {
		t.addLog("[red]✗ 后台服务未运行")
		t.addLog("[yellow]提示: 请重新启动程序或使用主菜单中的其他功能")
		return
	}

	// 获取当前配置
	cfg, err := t.client.ConfigGet()
	if err != nil {
		t.addLog("[red]✗ 获取配置失败: %v", err)
		t.addLog("[yellow]提示: 请检查后台服务状态")
		return
	}

	// 步骤 1: 配置监听端口
	t.showInputDialogWithID("wizard-port",
		"步骤 1/6: VPN监听端口\n\n推荐: 8080 | 范围: 1-65535",
		fmt.Sprintf("%d", cfg.ServerPort),
		func(portStr string) {
			port, err := strconv.Atoi(portStr)
			if err != nil || port < 1 || port > 65535 {
				t.addLog("[red]✗ 端口号无效 (必须在 1-65535 之间)")
				return
			}

			resp, err := t.client.ConfigUpdate("server_port", float64(port))
			if err != nil || !resp.Success {
				t.addLog("[red]✗ 端口配置失败")
				return
			}
			t.addLog("[green]✓ 端口: %d", port)

			// 步骤 2: 配置VPN网段
			t.showInputDialogWithID("wizard-network",
				"步骤 2/6: VPN网段 (CIDR格式)\n\n推荐: 10.8.0.0/24\n示例: 192.168.100.0/24",
				cfg.Network,
				func(network string) {
					// 验证网段格式
					_, _, err := net.ParseCIDR(network)
					if err != nil {
						t.addLog("[red]✗ 网段格式无效 (请使用CIDR格式，如: 10.8.0.0/24)")
						return
					}

					resp, err := t.client.ConfigUpdate("network", network)
					if err != nil || !resp.Success {
						t.addLog("[red]✗ 网段配置失败")
						return
					}
					t.addLog("[green]✓ 网段: %s", network)

					// 步骤 3: 选择路由模式
					t.showChoiceDialog("wizard-route-mode",
						"步骤 3/6: 路由模式选择\n\n"+
							"[#00FFFF]分流模式 (Split Tunnel) [推荐][-]\n"+
							"  • 仅指定网段走VPN\n"+
							"  • 保持本地网络速度\n"+
							"  • 适合访问内网资源\n\n"+
							"[#FF00FF]全局模式 (Full Tunnel)[-]\n"+
							"  • 所有流量通过VPN\n"+
							"  • 隐藏真实IP地址\n"+
							"  • 适合完全代理场景\n\n"+
							"请选择路由模式:",
						"分流模式", "全局模式",
						func(useFullMode bool) {
							// 应用基础路由配置
							if useFullMode {
								t.client.ConfigUpdate("route_mode", "full")
								t.client.ConfigUpdate("enable_nat", true)
								t.client.ConfigUpdate("redirect_gateway", true)
								t.addLog("[green]✓ 路由模式: [#FF00FF]全局[-] (所有流量)")

								// 全局模式：步骤 4 - 配置DNS
								t.showInputDialogWithID("wizard-dns",
									"步骤 4/6: DNS服务器配置\n\n"+
										"客户端将使用这些DNS服务器\n"+
										"多个DNS用逗号分隔\n\n"+
										"常用DNS:\n"+
										"  • 8.8.8.8,8.8.4.4 (Google)\n"+
										"  • 1.1.1.1,1.0.0.1 (Cloudflare)\n"+
										"  • 223.5.5.5,223.6.6.6 (阿里)",
									"8.8.8.8,8.8.4.4",
									func(dnsInput string) {
										// 解析DNS列表
										dnsServers := []interface{}{}
										for _, dns := range strings.Split(dnsInput, ",") {
											dns = strings.TrimSpace(dns)
											if dns != "" {
												dnsServers = append(dnsServers, dns)
											}
										}
										if len(dnsServers) > 0 {
											t.client.ConfigUpdate("dns_servers", dnsServers)
											// 同时启用DNS劫持，否则客户端不会应用DNS设置
											t.client.ConfigUpdate("redirect_dns", true)
											t.addLog("[green]✓ DNS服务器: %s", dnsInput)
											t.addLog("[green]✓ DNS劫持: 已启用")
										} else {
											t.addLog("[yellow]! DNS未配置，使用系统默认")
										}

										// 继续到最终确认
										executeServerWizardFinal(t, port, network, true, dnsInput, "")
									})
							} else {
								t.client.ConfigUpdate("route_mode", "split")
								t.client.ConfigUpdate("enable_nat", true)
								t.client.ConfigUpdate("redirect_gateway", false)
								t.addLog("[green]✓ 路由模式: [#00FFFF]分流[-] (指定网段)")

								// 分流模式：步骤 4 - 配置推送路由
								t.showInputDialogWithID("wizard-push-routes",
									"步骤 4/6: 推送路由配置\n\n"+
										"客户端通过VPN访问的网段\n"+
										"多个网段用逗号分隔\n\n"+
										"示例:\n"+
										"  • 192.168.1.0/24 (单个网段)\n"+
										"  • 192.168.0.0/16,10.0.0.0/8 (多个网段)\n\n"+
										"留空则只能访问VPN网段内的设备",
									"",
									func(routesInput string) {
										// 解析路由列表
										pushRoutes := []interface{}{}
										for _, route := range strings.Split(routesInput, ",") {
											route = strings.TrimSpace(route)
											if route != "" {
												// 验证格式
												if _, _, err := net.ParseCIDR(route); err == nil {
													pushRoutes = append(pushRoutes, route)
												}
											}
										}
										if len(pushRoutes) > 0 {
											t.client.ConfigUpdate("push_routes", pushRoutes)
											t.addLog("[green]✓ 推送路由: %s", routesInput)
										} else {
											t.addLog("[yellow]! 未配置推送路由，客户端只能访问VPN网段")
										}

										// 继续到最终确认
										executeServerWizardFinal(t, port, network, false, "", routesInput)
									})
							}
						})
				})
		})
}

// executeServerWizardFinal 服务端向导最终确认和部署
func executeServerWizardFinal(t *TUIApp, port int, network string, isFullMode bool, dnsServers string, pushRoutes string) {
	// 构建配置摘要
	modeStr := "分流"
	extraInfo := ""
	if isFullMode {
		modeStr = "全局"
		if dnsServers != "" {
			extraInfo = fmt.Sprintf("  DNS: [#39FF14]%s[-]\n", dnsServers)
		}
	} else {
		if pushRoutes != "" {
			extraInfo = fmt.Sprintf("  推送路由: [#39FF14]%s[-]\n", pushRoutes)
		} else {
			extraInfo = "  推送路由: [#FFE900]无 (仅VPN网段)[-]\n"
		}
	}

	// 步骤 5: 最终确认
	t.showChoiceDialog("wizard-final-confirm",
		"步骤 5/6: 确认部署\n\n"+
			"即将执行以下操作:\n"+
			"  [#00FFFF]1.[-] 初始化CA证书\n"+
			"  [#00FFFF]2.[-] 生成服务器证书\n"+
			"  [#00FFFF]3.[-] 启动VPN服务端\n\n"+
			"[#FFE900]配置信息:[-]\n"+
			fmt.Sprintf("  端口: [#39FF14]%d[-]\n", port)+
			fmt.Sprintf("  网段: [#39FF14]%s[-]\n", network)+
			fmt.Sprintf("  模式: [#39FF14]%s[-]\n", modeStr)+
			extraInfo+
			"\n确认开始部署?",
		"取消", "开始部署",
		func(confirmed bool) {
			if !confirmed {
				t.addLog("[yellow]已取消部署")
				return
			}

			// 开始部署
			go func() {
				t.addLog("")
				t.addLog("[cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
				t.addLog("[cyan]开始部署服务端...")
				t.addLog("[cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

				// 初始化 CA
				t.addLog("[cyan]→ 正在生成CA证书和服务器证书...")
				resp, err := t.client.CertInitCA()
				if err != nil {
					t.addLog("[red]✗ 证书生成失败: %v", err)
					t.addLog("")
					t.addLog("[yellow]提示: 可以在 '证书管理' 菜单中重新初始化")
					return
				}
				if !resp.Success {
					t.addLog("[red]✗ 证书生成失败: %s", resp.Error)
					return
				}
				t.addLog("[green]✓ CA证书和服务器证书已生成")

				// 启动服务端
				time.Sleep(500 * time.Millisecond)
				t.addLog("[cyan]→ 正在启动VPN服务端...")
				handleServerStart(t)

				// 完成提示
				time.Sleep(800 * time.Millisecond)
				t.addLog("")
				t.addLog("[cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
				t.addLog("[green]✓ 服务端部署完成!")
				t.addLog("[cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
				t.addLog("")

				// 步骤 6: 询问是否生成Token
				t.app.QueueUpdateDraw(func() {
					t.showChoiceDialog("wizard-gen-token",
						"步骤 6/6: 生成客户端Token\n\n"+
							"Token用于客户端申请证书\n"+
							"每个客户端需要一个Token\n\n"+
							"是否现在生成一个Token?",
						"稍后生成", "立即生成",
						func(genToken bool) {
							if !genToken {
								t.addLog("[yellow]提示: 可以稍后在 'Token管理' 菜单生成Token")
								showServerWizardComplete(t, port)
								return
							}

							// 询问客户端名称
							t.showInputDialogWithID("wizard-token-name",
								"输入客户端名称\n\n"+
									"用于标识这个Token属于哪个客户端\n\n"+
									"示例: client-01, 张三-手机, 办公室电脑",
								"client-01",
								func(clientName string) {
									if clientName == "" {
										clientName = "client-01"
									}

									// 询问有效期
									t.showInputDialogWithID("wizard-token-duration",
										"Token有效期 (小时)\n\n"+
											"Token过期后无法使用\n\n"+
											"建议:\n"+
											"  • 24 小时 (临时使用)\n"+
											"  • 72 小时 (3天)\n"+
											"  • 168 小时 (1周)\n"+
											"  • 720 小时 (1个月)",
										"24",
										func(durationStr string) {
											duration, err := strconv.Atoi(durationStr)
											if err != nil || duration <= 0 {
												duration = 24
											}

											// 生成Token
											t.addLog("[cyan]→ 正在生成Token...")
											token, err := t.client.TokenGenerate(clientName, duration)
											if err != nil {
												t.addLog("[red]✗ Token生成失败: %v", err)
												showServerWizardComplete(t, port)
												return
											}

											t.addLog("")
											t.addLog("[green]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
											t.addLog("[green]✓ Token已生成!")
											t.addLog("[green]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
											t.addLog("")
											t.addLog("[cyan]客户端名称: [#39FF14]%s[-]", clientName)
											t.addLog("[cyan]有效期: [#39FF14]%d 小时[-]", duration)
											t.addLog("[cyan]过期时间: [#39FF14]%s[-]", token.ExpiresAt.Format("2006-01-02 15:04:05"))
											t.addLog("")
											t.addLog("[#FFE900]━━━━ 完整Token (发给客户端) ━━━━[-]")
											t.addLog("[#39FF14]%s:%s[-]", token.TokenID, token.TokenKey)
											t.addLog("[#FFE900]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[-]")
											t.addLog("")
											t.addLog("[yellow]请将上面的Token安全地发送给客户端用户")
											t.addLog("[yellow]Token文件已保存到: %s", token.FilePath)

											showServerWizardComplete(t, port)
										})
								})
						})
				})
			}()
		})
}

// showServerWizardComplete 显示服务端向导完成提示
func showServerWizardComplete(t *TUIApp, port int) {
	t.addLog("")
	t.addLog("[cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	t.addLog("[green]服务端快速部署全部完成!")
	t.addLog("[cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	t.addLog("")
	t.addLog("[yellow]后续操作:")
	t.addLog("  [#00FFFF]•[-] 确保防火墙开放端口 %d", port)
	t.addLog("  [#00FFFF]•[-] 在 'Token管理' 可以生成更多Token")
	t.addLog("  [#00FFFF]•[-] 在 '服务端管理' 查看连接的客户端")
	t.addLog("")
}

func handleClientWizard(t *TUIApp) {
	t.addLog("开始客户端快速配置向导...")
	t.addLog("[cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	// 检查后台服务是否运行
	if !t.client.IsServiceRunning() {
		t.addLog("[red]✗ 后台服务未运行")
		t.addLog("[yellow]提示: 请重新启动程序")
		return
	}

	// 获取当前配置
	cfg, err := t.client.ConfigGet()
	if err != nil {
		t.addLog("[red]✗ 获取配置失败: %v", err)
		return
	}

	// 步骤 1: 配置服务器地址
	t.showInputDialogWithID("client-wizard-address",
		"步骤 1/6: VPN服务器地址\n\n"+
			"输入服务端的IP地址或域名\n\n"+
			"示例:\n"+
			"  • 192.168.1.100 (局域网IP)\n"+
			"  • vpn.example.com (域名)\n"+
			"  • 1.2.3.4 (公网IP)",
		cfg.ServerAddress,
		func(addr string) {
			if addr == "" {
				t.addLog("[red]✗ 服务器地址不能为空")
				return
			}

			resp, err := t.client.ConfigUpdate("server_address", addr)
			if err != nil || !resp.Success {
				t.addLog("[red]✗ 服务器地址配置失败")
				return
			}
			t.addLog("[green]✓ 服务器地址: %s", addr)

			// 步骤 2: 配置服务器端口
			t.showInputDialogWithID("client-wizard-port",
				"步骤 2/6: VPN服务器端口\n\n"+
					"服务端配置的监听端口\n\n"+
					"默认: 8080 | 范围: 1-65535",
				fmt.Sprintf("%d", cfg.ServerPort),
				func(portStr string) {
					port, err := strconv.Atoi(portStr)
					if err != nil || port < 1 || port > 65535 {
						t.addLog("[red]✗ 端口号无效")
						return
					}

					resp, err := t.client.ConfigUpdate("server_port", float64(port))
					if err != nil || !resp.Success {
						t.addLog("[red]✗ 端口配置失败")
						return
					}
					t.addLog("[green]✓ 服务器端口: %d", port)

					// 检查证书状态
					checkClientCertAndContinue(t, addr, port)
				})
		})
}

// checkClientCertAndContinue 检查客户端证书状态并继续向导
func checkClientCertAndContinue(t *TUIApp, serverAddr string, serverPort int) {
	// 检查证书
	list, _ := t.client.CertList()
	hasClientCert := false
	hasCA := false
	for _, f := range list.Files {
		if f.Name == "client.pem" && f.Exists {
			hasClientCert = true
		}
		if f.Name == "ca.pem" && f.Exists {
			hasCA = true
		}
	}

	if hasClientCert && hasCA {
		// 证书已就绪，直接询问是否连接
		t.addLog("")
		t.addLog("[green]✓ 客户端证书已就绪")
		t.addLog("")
		t.showChoiceDialog("client-wizard-connect",
			"步骤 3/6: 连接VPN\n\n"+
				"[#39FF14]证书已就绪（跳过步骤4-5）[-]\n\n"+
				"可以连接到VPN服务器\n\n"+
				fmt.Sprintf("服务器: [#39FF14]%s:%d[-]\n\n", serverAddr, serverPort)+
				"是否立即连接?",
			"稍后连接", "立即连接",
			func(connect bool) {
				if connect {
					t.addLog("[cyan]正在连接到 %s:%d...", serverAddr, serverPort)
					handleClientConnect(t)
				} else {
					t.addLog("[yellow]可以稍后在 '客户端管理' 菜单中连接VPN")
				}
			})
	} else {
		// 需要申请证书
		t.addLog("")
		t.addLog("[yellow]未找到客户端证书，需要申请")
		t.addLog("")

		t.showChoiceDialog("client-wizard-cert-choice",
			"步骤 3/6: 证书申请\n\n"+
				"[#FFE900]客户端需要证书才能连接VPN[-]\n\n"+
				"申请步骤:\n"+
				"  1. 生成证书签名请求(CSR)\n"+
				"  2. 输入服务端提供的Token\n"+
				"  3. 自动从服务端获取证书\n\n"+
				"[#00FFFF]请确保已从服务端管理员获取Token[-]\n\n"+
				"是否现在申请证书?",
			"稍后申请", "立即申请",
			func(apply bool) {
				if !apply {
					t.addLog("[yellow]提示: 可以在 '证书管理' 菜单中申请证书")
					return
				}

				// 开始证书申请流程
				startClientCertApplication(t, serverAddr, serverPort)
			})
	}
}

// startClientCertApplication 开始客户端证书申请流程
func startClientCertApplication(t *TUIApp, serverAddr string, serverPort int) {
	// 询问客户端名称（用于CSR）
	t.showInputDialogWithID("client-wizard-csr-name",
		"步骤 4/6: 输入客户端名称\n\n"+
			"用于生成证书签名请求(CSR)\n\n"+
			"示例: my-laptop, 张三-手机",
		"client",
		func(clientName string) {
			if clientName == "" {
				clientName = "client"
			}

			// 生成CSR
			t.addLog("[cyan]→ 正在生成证书签名请求(CSR)...")
			csrResp, err := t.client.CertGenCSR(clientName)
			if err != nil {
				t.addLog("[red]✗ CSR生成失败: %v", err)
				return
			}
			t.addLog("[green]✓ CSR已生成: %s", csrResp.CSRFile)

			// 步骤 5: 输入Token
			t.showInputDialogWithID("client-wizard-token",
				"步骤 5/6: 输入Token\n\n"+
					"[#FFE900]请输入服务端管理员提供的Token[-]\n\n"+
					"Token格式:\n"+
					"  完整格式: ID:KEY\n"+
					"  示例: client-01-20260125:abc123...\n\n"+
					"[#00FFFF]提示: 直接粘贴完整Token即可[-]",
				"",
				func(tokenInput string) {
					tokenInput = strings.TrimSpace(tokenInput)
					if tokenInput == "" {
						t.addLog("[red]✗ Token不能为空")
						return
					}

					// 解析Token
					var tokenID, tokenKey string
					if strings.Contains(tokenInput, ":") {
						parts := strings.SplitN(tokenInput, ":", 2)
						tokenID = strings.TrimSpace(parts[0])
						tokenKey = strings.TrimSpace(parts[1])
					} else {
						t.addLog("[red]✗ Token格式错误，请使用 ID:KEY 格式")
						return
					}

					if tokenID == "" || tokenKey == "" {
						t.addLog("[red]✗ Token格式错误")
						return
					}

					t.addLog("[green]✓ Token已解析: %s", tokenID)

					// 申请证书
					t.addLog("[cyan]→ 正在从服务端申请证书...")

					// 构建证书申请请求
					req := RequestCertRequest{
						CSRFile:       csrResp.CSRFile, // 使用生成的CSR文件路径
						ServerAddress: serverAddr,
						ServerPort:    8081, // 证书API端口
						TokenID:       tokenID,
						TokenKey:      tokenKey,
					}

					certResp, err := t.client.CertRequest(req)
					if err != nil {
						t.addLog("[red]✗ 证书申请失败: %v", err)
						t.addLog("[yellow]提示: 请检查Token是否正确，服务端是否在运行")
						return
					}
					if !certResp.Success {
						t.addLog("[red]✗ 证书申请失败: %s", certResp.Error)
						return
					}

					t.addLog("[green]✓ 证书申请成功!")
					t.addLog("[green]✓ 证书已保存到 ./certs 目录")
					t.addLog("")

					// 步骤 6: 连接VPN
					t.showChoiceDialog("client-wizard-final-connect",
						"步骤 6/6: 连接VPN\n\n"+
							"[#39FF14]证书申请成功![-]\n\n"+
							fmt.Sprintf("服务器: [#39FF14]%s:%d[-]\n\n", serverAddr, serverPort)+
							"是否立即连接到VPN服务器?",
						"稍后连接", "立即连接",
						func(connect bool) {
							if connect {
								t.addLog("[cyan]正在连接到 %s:%d...", serverAddr, serverPort)
								handleClientConnect(t)
							} else {
								showClientWizardComplete(t)
							}
						})
				})
		})
}

// showClientWizardComplete 显示客户端向导完成提示
func showClientWizardComplete(t *TUIApp) {
	t.addLog("")
	t.addLog("[cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	t.addLog("[green]客户端配置完成!")
	t.addLog("[cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	t.addLog("")
	t.addLog("[yellow]后续操作:")
	t.addLog("  [#00FFFF]•[-] 在 '客户端管理' 菜单连接VPN")
	t.addLog("  [#00FFFF]•[-] 连接后可以在状态栏查看连接状态")
	t.addLog("")
}

// ================ 系统处理 ================

func handleExit(t *TUIApp) {
	t.RequestExit()
}

// ================ 辅助函数 ================

func parseJSON(data []byte, v interface{}) {
	if data != nil {
		json.Unmarshal(data, v)
	}
}
