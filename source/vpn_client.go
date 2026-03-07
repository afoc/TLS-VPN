package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// VPNClient VPN客户端结构
type VPNClient struct {
	tlsConfig     *tls.Config
	conn          *tls.Conn
	connMutex     sync.Mutex
	assignedIP    net.IP
	reconnect     int32 // 使用 atomic，1=true, 0=false
	config        VPNConfig
	packetHandler func([]byte) error
	cancel        context.CancelFunc // 主 context 取消函数
	cancelMutex   sync.Mutex
	tunDevice     TUNDevice // 统一的TUN设备接口
	reader        *bufio.Reader
	routeManager  *RouteManager // 路由管理器
	retryCount    int           // 重连计数器
}

// NewVPNClient 创建新的VPN客户端
func NewVPNClient(certManager *CertificateManager, config VPNConfig) *VPNClient {
	return &VPNClient{
		tlsConfig:     certManager.ClientTLSConfig(),
		reconnect:     1, // 1 表示 true
		config:        config,
		packetHandler: nil,
	}
}

// InitializeTUN 初始化TUN设备
func (c *VPNClient) InitializeTUN() error {
	// 检查root权限
	if err := checkRootPrivileges(); err != nil {
		return err
	}

	// 客户端使用默认网络配置创建TUN设备（实际IP由服务器分配）
	// 如果配置中没有 Network，使用默认值
	network := c.config.Network
	if network == "" {
		network = "10.8.0.0/24" // 客户端默认使用这个网段创建TUN
		log.Printf("客户端使用默认网络配置: %s", network)
	}

	// 创建TUN设备（自动选择可用名称，传入网络配置）
	tun, err := createTUNDevice("tun", network)
	if err != nil {
		return err
	}
	c.tunDevice = tun

	log.Printf("客户端TUN设备已创建: %s，等待IP分配...", tun.Name())
	return nil
}

// ConfigureTUN 配置TUN设备（在获得IP后调用）
func (c *VPNClient) ConfigureTUN() error {
	if c.tunDevice == nil {
		return fmt.Errorf("TUN设备未创建")
	}
	if c.assignedIP == nil {
		return fmt.Errorf("未分配IP地址")
	}

	// 从配置中获取实际的子网掩码
	_, ipNet, err := net.ParseCIDR(c.config.Network)
	if err != nil {
		return fmt.Errorf("解析网络配置失败: %v", err)
	}
	maskSize, _ := ipNet.Mask.Size()

	// 配置TUN设备IP地址
	ipAddr := fmt.Sprintf("%s/%d", c.assignedIP.String(), maskSize)
	if err := configureTUNDevice(c.tunDevice.Name(), ipAddr, c.config.MTU); err != nil {
		return err
	}

	log.Printf("客户端TUN设备已配置: %s", ipAddr)
	return nil
}

// Connect 连接到VPN服务器（支持 context 超时/取消）
func (c *VPNClient) Connect(ctx context.Context) error {
	address := fmt.Sprintf("%s:%d", c.config.ServerAddress, c.config.ServerPort)

	// 使用带超时的 dialer
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	netConn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return fmt.Errorf("连接失败: %v", err)
	}

	// 升级为 TLS 连接
	conn := tls.Client(netConn, c.tlsConfig)

	err = conn.Handshake()
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("TLS握手失败: %v", err)
	}

	// 验证TLS版本
	if conn.ConnectionState().Version != tls.VersionTLS13 {
		_ = conn.Close()
		return fmt.Errorf("未使用TLS 1.3协议")
	}

	c.connMutex.Lock()
	c.conn = conn
	c.reader = bufio.NewReader(conn)
	c.connMutex.Unlock()
	log.Println("成功连接到VPN服务器，使用TLS 1.3协议")

	msg, err := ReadMessage(c.reader)
	if err != nil {
		return fmt.Errorf("读取IP分配消息失败: %v", err)
	}

	if msg.Type == MessageTypeIPAssignment && len(msg.Payload) >= 4 {
		c.assignedIP = net.IP(msg.Payload)
		log.Printf("分配的VPN IP: %s", c.assignedIP)
	} else {
		return fmt.Errorf("未收到有效的IP分配信息: type=%d, length=%d", msg.Type, msg.Length)
	}

	// 接收服务器推送的配置
	msg, err = ReadMessage(c.reader)
	if err != nil {
		log.Printf("警告：未接收到服务器配置: %v", err)
		return nil // 配置是可选的，不影响连接
	}

	if msg.Type == MessageTypeControl && msg.Length > 0 {
		var serverConfig ClientConfig
		if err := json.Unmarshal(msg.Payload, &serverConfig); err != nil {
			log.Printf("警告：解析服务器配置失败: %v", err)
		} else {
			// 应用服务器推送的路由配置
			if serverConfig.RouteMode != "" {
				c.config.RouteMode = serverConfig.RouteMode
				log.Printf("服务器配置路由模式: %s", serverConfig.RouteMode)
			}
			if len(serverConfig.ExcludeRoutes) > 0 {
				c.config.ExcludeRoutes = serverConfig.ExcludeRoutes
			}
			c.config.RedirectGateway = serverConfig.RedirectGateway
			c.config.RedirectDNS = serverConfig.RedirectDNS
			if len(serverConfig.DNS) > 0 {
				c.config.DNSServers = serverConfig.DNS
			}
			if len(serverConfig.Routes) > 0 {
				c.config.PushRoutes = serverConfig.Routes
			}
			// 保存ServerIP供路由设置使用
			if serverConfig.ServerIP != "" {
				c.config.ServerIP = serverConfig.ServerIP
			}
			log.Printf("已应用服务器配置: RouteMode=%s, RedirectGateway=%v, RedirectDNS=%v",
				c.config.RouteMode, c.config.RedirectGateway, c.config.RedirectDNS)
		}
	}

	return nil
}

// SendData 发送数据
func (c *VPNClient) SendData(data []byte) error {
	c.connMutex.Lock()
	conn := c.conn
	c.connMutex.Unlock()

	if conn == nil {
		return fmt.Errorf("连接未建立")
	}

	msg := &Message{
		Type:    MessageTypeData,
		Length:  uint32(len(data)),
		Payload: data,
	}

	serialized, err := msg.Serialize()
	if err != nil {
		return fmt.Errorf("序列化消息失败: %v", err)
	}

	_, err = conn.Write(serialized)
	return err
}

// SendHeartbeat 发送心跳
func (c *VPNClient) SendHeartbeat() error {
	c.connMutex.Lock()
	conn := c.conn
	c.connMutex.Unlock()

	if conn == nil {
		return fmt.Errorf("连接未建立")
	}

	msg := &Message{
		Type:    MessageTypeHeartbeat,
		Length:  0,
		Payload: []byte{},
	}

	serialized, err := msg.Serialize()
	if err != nil {
		return fmt.Errorf("序列化心跳消息失败: %v", err)
	}

	_, err = conn.Write(serialized)
	return err
}

// ReceiveData 接收数据，返回消息类型和数据
func (c *VPNClient) ReceiveData() (MessageType, []byte, error) {
	c.connMutex.Lock()
	reader := c.reader
	c.connMutex.Unlock()

	if reader == nil {
		return 0, nil, fmt.Errorf("连接未建立")
	}

	msg, err := ReadMessage(reader)
	if err != nil {
		return 0, nil, err
	}

	return msg.Type, msg.Payload, nil
}

// Run 运行客户端（接受 context 控制生命周期）
func (c *VPNClient) Run(ctx context.Context) {
	maxRetries := c.config.MaxRetries // 0 表示无限重连

	// 保存 cancel 函数供 Close() 使用
	c.cancelMutex.Lock()
	ctx, c.cancel = context.WithCancel(ctx)
	c.cancelMutex.Unlock()

	defer func() {
		c.cancelMutex.Lock()
		c.cancel = nil
		c.cancelMutex.Unlock()
	}()

	for atomic.LoadInt32(&c.reconnect) == 1 {
		// 检查是否被取消
		select {
		case <-ctx.Done():
			log.Println("收到停止信号，退出客户端...")
			return
		default:
		}

		err := c.Connect(ctx)
		if err != nil {
			// 检查是否是因为 context 取消
			if ctx.Err() != nil {
				return
			}
			c.retryCount++
			if maxRetries > 0 && c.retryCount >= maxRetries {
				log.Printf("连接失败: %v，已达最大重试次数(%d)，停止重连", err, maxRetries)
				atomic.StoreInt32(&c.reconnect, 0)
				break
			}
			log.Printf("连接失败: %v，%v秒后重试 (%d/%d)", err, c.config.ReconnectDelay/time.Second, c.retryCount, maxRetries)

			// 可中断的等待
			select {
			case <-ctx.Done():
				return
			case <-time.After(c.config.ReconnectDelay):
			}
			continue
		}

		// 连接成功，重置计数器
		c.retryCount = 0
		log.Println("VPN客户端已连接，开始数据传输...")

		// 如果有TUN设备，配置它
		if c.tunDevice != nil && c.assignedIP != nil {
			if err := c.ConfigureTUN(); err != nil {
				log.Printf("配置TUN设备失败: %v", err)
				c.closeConnection()
				continue
			}

			// 配置路由
			if err := c.setupRoutes(); err != nil {
				log.Printf("配置路由失败: %v", err)
				c.closeConnection()
				continue
			}
		}

		// 创建当前会话的 context（用于控制本次连接的所有协程）
		sessionCtx, sessionCancel := context.WithCancel(ctx)

		// 启动心跳协程
		go c.startHeartbeat(sessionCtx)

		// 如果有TUN设备，启动TUN读取协程
		if c.tunDevice != nil {
			go c.handleTUNRead(sessionCtx)
		}

		// 数据传输循环
		c.dataLoop(sessionCtx)

		// 停止本次会话的所有协程
		sessionCancel()

		// 关闭当前连接（重要：避免资源泄漏）
		c.closeConnection()

		// 检查是否需要重连
		if ctx.Err() != nil {
			return
		}

		if atomic.LoadInt32(&c.reconnect) == 1 {
			log.Println("连接断开，准备重连...")
			select {
			case <-ctx.Done():
				return
			case <-time.After(c.config.ReconnectDelay):
			}
		}
	}

	log.Println("VPN客户端已退出")
}

// startHeartbeat 开始心跳
func (c *VPNClient) startHeartbeat(ctx context.Context) {
	interval := c.config.HeartbeatInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.connMutex.Lock()
			conn := c.conn
			c.connMutex.Unlock()

			if conn == nil {
				return
			}

			// 发送心跳包
			err := c.SendHeartbeat()
			if err != nil {
				log.Printf("发送心跳失败: %v", err)
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

// handleTUNRead 处理从TUN设备读取的数据
func (c *VPNClient) handleTUNRead(ctx context.Context) {
	packet := make([]byte, c.config.MTU)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// 从TUN设备读取IP包（Windows Wintun和Unix/Linux TUN都是Layer 3）
		n, err := c.tunDevice.Read(packet)
		if err != nil {
			if ctx.Err() == nil {
				log.Printf("从TUN设备读取失败: %v", err)
			}
			return
		}

		if n < 20 { // IP header minimum size
			continue
		}

		// 发送数据包到服务器
		err = c.SendData(packet[:n])
		if err != nil {
			log.Printf("发送数据包失败: %v", err)
			return
		}
	}
}

// dataLoop 数据传输循环
func (c *VPNClient) dataLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		c.connMutex.Lock()
		conn := c.conn
		c.connMutex.Unlock()

		if conn == nil {
			return
		}

		_ = conn.SetReadDeadline(time.Now().Add(c.config.KeepAliveTimeout))

		msgType, data, err := c.ReceiveData()
		if err != nil {
			if ctx.Err() != nil {
				return // context 已取消
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				log.Printf("连接超时")
				return
			}
			log.Printf("读取数据失败: %v", err)
			return
		}

		// 处理心跳响应 - 不打印日志
		if msgType == MessageTypeHeartbeat {
			continue
		}

		// 处理控制消息
		if msgType == MessageTypeControl {
			if len(data) > 0 {
				var config ClientConfig
				if err := json.Unmarshal(data, &config); err != nil {
					log.Printf("解析服务器配置失败: %v", err)
				} else {
					if err := c.applyServerConfig(&config); err != nil {
						log.Printf("应用服务器配置失败: %v", err)
					}
				}
			}
			continue
		}

		// 处理数据包
		if msgType == MessageTypeData && data != nil && len(data) > 0 {
			if c.tunDevice != nil {
				// 直接写入TUN设备（Windows Wintun和Unix/Linux TUN都是Layer 3）
				_, err := c.tunDevice.Write(data)
				if err != nil {
					log.Printf("写入TUN设备失败: %v", err)
				}
			} else if c.packetHandler != nil {
				// 使用自定义处理器
				err := c.packetHandler(data)
				if err != nil {
					log.Printf("处理数据包失败: %v", err)
				}
			} else {
				// 默认处理：打印数据包信息
				log.Printf("接收到数据包，长度: %d, 内容: %s", len(data), hex.EncodeToString(data[:min(len(data), 16)]))
			}
		}
	}
}

// setupRoutes 设置路由（根据配置模式）
func (c *VPNClient) setupRoutes() error {
	// 创建路由管理器
	rm, err := NewRouteManager()
	if err != nil {
		return fmt.Errorf("创建路由管理器失败: %v", err)
	}
	c.routeManager = rm

	// 获取服务器IP（去掉CIDR后缀）
	serverIP := c.config.ServerAddress

	// 添加到VPN服务器的路由，确保不走VPN
	// 只有当服务器IP不是本地地址时才添加
	if serverIP != "" && serverIP != "127.0.0.1" && serverIP != "localhost" {
		serverRoute := serverIP + "/32"
		// 确保默认网关和接口都有效
		if rm.defaultGateway != "" && rm.defaultIface != "" {
			if err := rm.AddRoute(serverRoute, rm.defaultGateway, rm.defaultIface); err != nil {
				// 静默处理，因为这个路由不是必需的（服务器可能在同一网络）
				log.Printf("跳过添加到VPN服务器的路由（可能不需要）: %s", serverIP)
			}
		}
	}

	// 根据路由模式设置路由
	switch c.config.RouteMode {
	case "full":
		return c.setupFullTunnelRoutes(rm)
	case "split":
		return c.setupSplitTunnelRoutes(rm)
	default:
		log.Printf("警告：未知的路由模式 %s，使用分流模式", c.config.RouteMode)
		return c.setupSplitTunnelRoutes(rm)
	}
}

// setupFullTunnelRoutes 设置全流量模式路由
func (c *VPNClient) setupFullTunnelRoutes(rm *RouteManager) error {
	log.Println("配置全流量代理模式...")

	// 获取VPN网关（服务器在VPN网络中的IP）
	vpnGateway := ""
	if c.config.ServerIP != "" {
		// 解析服务器IP，去掉CIDR
		for i := 0; i < len(c.config.ServerIP); i++ {
			if c.config.ServerIP[i] == '/' {
				vpnGateway = c.config.ServerIP[:i]
				break
			}
		}
	}
	if vpnGateway == "" {
		vpnGateway = "10.8.0.1" // 默认值
	}

	// 使用TUN设备名称（Wintun设备名称）
	tunDeviceName := c.tunDevice.Name()

	// 添加 0.0.0.0/1 和 128.0.0.0/1 路由（覆盖所有IP）
	routes := []string{"0.0.0.0/1", "128.0.0.0/1"}
	for _, route := range routes {
		// 检查是否被排除
		if c.isExcluded(route) {
			log.Printf("跳过被排除的路由: %s", route)
			continue
		}

		if err := rm.AddRoute(route, vpnGateway, tunDeviceName); err != nil {
			log.Printf("警告：添加路由 %s 失败: %v", route, err)
		}
	}

	// 处理排除路由 - 添加到原始网关
	for _, excludeRoute := range c.config.ExcludeRoutes {
		if err := rm.AddRoute(excludeRoute, rm.defaultGateway, rm.defaultIface); err != nil {
			log.Printf("警告：添加排除路由 %s 失败: %v", excludeRoute, err)
		}
	}

	// 配置DNS（如果启用）
	if c.config.RedirectDNS && len(c.config.DNSServers) > 0 {
		if err := rm.SaveDNS(); err != nil {
			log.Printf("警告：保存DNS配置失败: %v", err)
		} else {
			// Windows上需要在VPN接口上设置DNS，而不是物理网卡
			tunDeviceName := c.tunDevice.Name()
			if err := rm.SetDNSForInterface(c.config.DNSServers, tunDeviceName); err != nil {
				log.Printf("警告：设置DNS失败: %v", err)
			}
		}
	}

	log.Println("全流量代理模式配置完成")
	return nil
}

// setupSplitTunnelRoutes 设置分流模式路由
func (c *VPNClient) setupSplitTunnelRoutes(rm *RouteManager) error {
	log.Println("配置分流模式...")

	// 获取VPN网关
	vpnGateway := ""
	if c.config.ServerIP != "" {
		for i := 0; i < len(c.config.ServerIP); i++ {
			if c.config.ServerIP[i] == '/' {
				vpnGateway = c.config.ServerIP[:i]
				break
			}
		}
	}
	if vpnGateway == "" {
		vpnGateway = "10.8.0.1"
	}

	// 使用TUN设备名称
	tunDeviceName := c.tunDevice.Name()

	// 只添加 push_routes 中的路由
	for _, route := range c.config.PushRoutes {
		if err := rm.AddRoute(route, vpnGateway, tunDeviceName); err != nil {
			log.Printf("警告：添加路由 %s 失败: %v", route, err)
		}
	}

	log.Printf("分流模式配置完成，已添加 %d 条路由", len(c.config.PushRoutes))
	return nil
}

// isExcluded 检查路由是否被排除
func (c *VPNClient) isExcluded(route string) bool {
	for _, excludeRoute := range c.config.ExcludeRoutes {
		if route == excludeRoute {
			return true
		}
	}
	return false
}

// closeConnection 关闭当前连接（不停止整个客户端，用于重连场景）
func (c *VPNClient) closeConnection() {
	c.connMutex.Lock()
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
	c.reader = nil
	c.connMutex.Unlock()
}

// Close 关闭客户端（完全停止）
func (c *VPNClient) Close() {
	atomic.StoreInt32(&c.reconnect, 0)

	// 取消所有协程
	c.cancelMutex.Lock()
	if c.cancel != nil {
		c.cancel()
	}
	c.cancelMutex.Unlock()

	// 清理路由和DNS
	if c.routeManager != nil {
		c.routeManager.CleanupRoutes()
		_ = c.routeManager.RestoreDNS()
	}

	// 关闭连接
	c.closeConnection()

	// 清理TUN设备（这也会使 handleTUNRead 中的阻塞 Read 返回错误）
	if c.tunDevice != nil {
		deviceName := c.tunDevice.Name()
		_ = c.tunDevice.Close()
		cleanupTUNDevice(deviceName)
	}
}

// IsRunning 检查客户端是否在运行
func (c *VPNClient) IsRunning() bool {
	c.cancelMutex.Lock()
	defer c.cancelMutex.Unlock()
	return c.cancel != nil
}

// applyServerConfig 应用服务器推送的配置
func (c *VPNClient) applyServerConfig(config *ClientConfig) error {
	log.Printf("收到服务器配置: DNS=%v, Routes=%v, MTU=%d", config.DNS, config.Routes, config.MTU)

	// 记录DNS服务器
	for _, dns := range config.DNS {
		log.Printf("推荐DNS: %s", dns)
	}

	if len(config.Routes) == 0 {
		return nil
	}

	// 确保路由管理器已初始化
	if c.routeManager == nil {
		rm, err := NewRouteManager()
		if err != nil {
			return fmt.Errorf("创建路由管理器失败: %v", err)
		}
		c.routeManager = rm
	}

	// 解析服务器VPN IP（去掉CIDR后缀）作为路由网关
	serverIPStr := config.ServerIP
	for i := 0; i < len(serverIPStr); i++ {
		if serverIPStr[i] == '/' {
			serverIPStr = serverIPStr[:i]
			break
		}
	}
	if serverIPStr == "" {
		serverIPStr = "10.8.0.1"
	}

	tunDeviceName := c.tunDevice.Name()
	for _, route := range config.Routes {
		if err := c.routeManager.AddRoute(route, serverIPStr, tunDeviceName); err != nil {
			log.Printf("警告：添加路由 %s 失败: %v", route, err)
		} else {
			log.Printf("已添加路由: %s via %s dev %s", route, serverIPStr, tunDeviceName)
		}
	}

	return nil
}
