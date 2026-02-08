package main

// MenuItem 菜单项定义
type MenuItem struct {
	Label    string
	Desc     string
	Shortcut rune
	NavTo    string        // 导航到子菜单（如果非空）
	Handler  func(*TUIApp) // 处理函数（如果 NavTo 为空）
}

// MenuDef 菜单定义
type MenuDef struct {
	Title  string
	Parent string // 为空表示顶级菜单
	Items  []MenuItem
}

// GetMenus 返回所有菜单定义（使用函数避免初始化循环）
func GetMenus() map[string]MenuDef {
	return map[string]MenuDef{
		// ================ 主菜单 ================
		"main": {
			Title: "主菜单",
			Items: []MenuItem{
				{"◈ 服务端模式", "管理VPN服务端", '1', "server", nil},
				{"◇ 客户端模式", "管理VPN客户端", '2', "client", nil},
				{"⚙ 配置管理", "保存/加载配置", '3', "config", nil},
				{"★ 快速向导", "快速部署VPN", '4', "wizard", nil},
				{"✖ 退出", "退出管理界面", 'q', "", handleExit},
			},
		},

		// ================ 服务端菜单 ================
		"server": {
			Title:  "◈ 服务端模式",
			Parent: "main",
			Items: []MenuItem{
				{"▶ 启动服务端", "启动VPN服务", '1', "", handleServerStart},
				{"■ 停止服务端", "停止VPN服务", '2', "", handleServerStop},
				{"⚙ 服务端设置", "配置服务端参数", '3', "server_settings", nil},
				{"⬡ CA证书管理", "管理CA和服务端证书", '4', "server_cert", nil},
				{"◆ Token管理", "管理客户端Token", '5', "token", nil},
				{"⬢ 查看在线客户端", "显示当前连接的客户端", '6', "", handleShowClients},
				{"⊗ 踢出客户端", "断开指定客户端连接", '7', "", handleKickClient},
				{"▤ 流量统计", "查看流量统计信息", '8', "", handleShowStats},
			},
		},

		"server_settings": {
			Title:  "⚙ 服务端设置",
			Parent: "server",
			Items: []MenuItem{
				{"◎ 修改监听端口", "当前端口: 动态显示", '1', "", handleSetPort},
				{"◎ 修改VPN网段", "当前网段: 动态显示", '2', "", handleSetNetwork},
				{"◎ 修改MTU", "当前MTU: 动态显示", '3', "", handleSetMTU},
				{"➤ 路由模式设置", "配置流量路由策略", '4', "route_mode", nil},
				{"◎ 修改NAT出口网卡", "配置NAT出口", '5', "", handleSetNATInterface},
				{"◎ 修改最大连接数", "限制并发连接", '6', "", handleSetMaxConnections},
			},
		},

		"route_mode": {
			Title:  "➤ 路由模式设置",
			Parent: "server_settings",
			Items: []MenuItem{
				{"◎ NAT模式", "全部流量通过服务端NAT", '1', "", handleSetRouteModeFull},
				{"◎ 分流模式", "仅指定网段走VPN", '2', "", handleSetRouteModeSplit},
				{"▣ 推送路由设置", "管理推送给客户端的路由", '3', "push_routes", nil},
				{"↻ 切换NAT开关", "启用/禁用NAT", '4', "", handleToggleNAT},
				{"◉ DNS设置", "配置DNS劫持和服务器", '5', "dns_settings", nil},
			},
		},

		"dns_settings": {
			Title:  "◉ DNS设置",
			Parent: "route_mode",
			Items: []MenuItem{
				{"↻ 切换DNS劫持开关", "启用/禁用客户端DNS劫持", '1', "", handleToggleDNS},
				{"✦ 修改DNS服务器", "设置推送给客户端的DNS", '2', "", handleSetDNSServers},
				{"◐ 查看当前DNS配置", "显示DNS设置详情", '3', "", handleShowDNSConfig},
			},
		},

		"push_routes": {
			Title:  "▣ 推送路由设置",
			Parent: "route_mode",
			Items: []MenuItem{
				{"◐ 查看当前路由", "显示已配置的路由", '1', "", handleShowPushRoutes},
				{"+ 添加推送网段", "添加新的路由规则", '+', "", handleAddPushRoute},
				{"- 清空所有路由", "删除所有路由规则", '-', "", handleClearPushRoutes},
			},
		},

		// ================ 证书菜单 ================
		"server_cert": {
			Title:  "⬡ CA证书管理",
			Parent: "server",
			Items: []MenuItem{
				{"✦ 初始化CA", "生成CA和服务端证书", '1', "", handleInitCA},
				{"▣ 查看证书列表", "显示所有证书文件", '2', "", handleShowCertList},
				{"⬢ 查看已签发客户端", "显示已签发的客户端证书", '3', "", handleShowSignedClients},
			},
		},

		// ================ Token菜单 ================
		"token": {
			Title:  "◆ Token管理",
			Parent: "server",
			Items: []MenuItem{
				{"✦ 生成新Token", "为客户端生成认证Token", '1', "", handleGenToken},
				{"▣ 查看Token列表", "显示所有Token", '2', "", handleShowTokenList},
				{"⊗ 删除Token", "删除指定Token", '3', "", handleDeleteToken},
				{"↻ 清理过期Token", "删除已过期/已使用的Token", '4', "", handleCleanupTokens},
			},
		},

		// ================ 客户端菜单 ================
		"client": {
			Title:  "◇ 客户端模式",
			Parent: "main",
			Items: []MenuItem{
				{"⚡ 连接VPN", "连接到VPN服务器", '1', "", handleClientConnect},
				{"⦸ 断开VPN", "断开当前VPN连接", '2', "", handleClientDisconnect},
				{"⚙ 客户端设置", "配置服务器地址等", '3', "client_settings", nil},
				{"⬡ 证书管理", "管理客户端证书", '4', "client_cert", nil},
				{"▣ 查看连接状态", "显示当前连接详情", '5', "", handleShowClientStatus},
			},
		},

		"client_settings": {
			Title:  "⚙ 客户端设置",
			Parent: "client",
			Items: []MenuItem{
				{"◎ 修改服务器地址", "设置VPN服务器地址", '1', "", handleSetServerAddress},
				{"◎ 修改服务器端口", "设置VPN服务器端口", '2', "", handleSetServerPort},
			},
		},

		"client_cert": {
			Title:  "⬡ 证书管理",
			Parent: "client",
			Items: []MenuItem{
				{"✦ 生成CSR", "生成证书签名请求", '1', "", handleGenCSR},
				{"➚ 使用Token申请证书", "从服务端获取证书", '2', "", handleRequestCert},
				{"◐ 查看本地证书", "显示证书文件状态", '3', "", handleShowClientCertStatus},
			},
		},

		// ================ 配置菜单 ================
		"config": {
			Title:  "⚙ 配置管理",
			Parent: "main",
			Items: []MenuItem{
				{"▼ 保存当前配置", "保存配置到文件", '1', "", handleSaveConfig},
				{"▲ 加载配置文件", "从文件加载配置", '2', "", handleLoadConfig},
				{"◐ 查看当前配置", "显示所有配置项", '3', "", handleShowConfig},
				{"↻ 恢复默认配置", "重置所有配置", '4', "", handleResetConfig},
			},
		},

		// ================ 向导菜单 ================
		"wizard": {
			Title:  "★ 快速向导",
			Parent: "main",
			Items: []MenuItem{
				{"◈ 服务端快速部署", "一键部署VPN服务端", '1', "", handleServerWizard},
				{"◇ 客户端快速配置", "一键配置VPN客户端", '2', "", handleClientWizard},
			},
		},
	}
}
