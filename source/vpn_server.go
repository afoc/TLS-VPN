package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	mathrand "math/rand"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// VPNSession VPN会话结构
type VPNSession struct {
	ID           string
	RemoteAddr   net.Addr
	TLSConn      *tls.Conn
	LastActivity time.Time
	IP           net.IP
	CertSubject  string // 证书主题，用于绑定IP
	closed       bool   // 标记会话是否已关闭
	mutex        sync.RWMutex
	sendSeq      uint32     // 新增：发送序列号
	recvSeq      uint32     // 新增：接收序列号
	seqMutex     sync.Mutex // 新增：序列号锁
	// 流量统计
	BytesSent     uint64    // 发送字节数
	BytesReceived uint64    // 接收字节数
	ConnectedAt   time.Time // 连接时间
}

// UpdateActivity 更新活动时间
func (s *VPNSession) UpdateActivity() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.LastActivity = time.Now()
}

// GetActivity 获取活动时间
func (s *VPNSession) GetActivity() time.Time {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.LastActivity
}

// IsClosed 检查会话是否已关闭
func (s *VPNSession) IsClosed() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.closed
}

// Close 关闭会话连接
func (s *VPNSession) Close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.closed {
		return nil // 已经关闭
	}
	s.closed = true
	if s.TLSConn != nil {
		return s.TLSConn.Close()
	}
	return nil
}

// AddBytesSent 增加发送字节数
func (s *VPNSession) AddBytesSent(n uint64) {
	atomic.AddUint64(&s.BytesSent, n)
}

// AddBytesReceived 增加接收字节数
func (s *VPNSession) AddBytesReceived(n uint64) {
	atomic.AddUint64(&s.BytesReceived, n)
}

// GetStats 获取会话统计信息
func (s *VPNSession) GetStats() (sent, received uint64, connTime time.Duration) {
	sent = atomic.LoadUint64(&s.BytesSent)
	received = atomic.LoadUint64(&s.BytesReceived)
	connTime = time.Since(s.ConnectedAt)
	return
}

// VPNServer VPN服务器结构
type VPNServer struct {
	listener      net.Listener
	tlsConfig     *tls.Config
	sessions      map[string]*VPNSession
	ipToSession   map[string]*VPNSession // IP到会话的快速映射
	sessionMutex  sync.RWMutex
	cancel        context.CancelFunc // 用于停止服务器
	cancelMutex   sync.Mutex
	vpnNetwork    *net.IPNet
	clientIPPool  *IPPool
	packetHandler func([]byte) error
	sessionCount  int64
	config        VPNConfig
	tunDevice     TUNDevice // 统一的TUN设备接口
	serverIP      net.IP
	natRules      []NATRule // NAT规则跟踪
}

// NewVPNServer 创建新的VPN服务器
func NewVPNServer(address string, certManager *CertificateManager, config VPNConfig) (*VPNServer, error) {
	// 验证配置
	if err := config.ValidateConfig(); err != nil {
		return nil, fmt.Errorf("配置验证失败: %v", err)
	}

	serverConfig := certManager.ServerTLSConfig()
	listener, err := tls.Listen("tcp", address, serverConfig)
	if err != nil {
		return nil, fmt.Errorf("监听失败: %v", err)
	}

	_, vpnNetwork, err := net.ParseCIDR(config.Network)
	if err != nil {
		return nil, fmt.Errorf("解析VPN网络失败: %v", err)
	}

	return &VPNServer{
		listener:     listener,
		tlsConfig:    serverConfig,
		sessions:     make(map[string]*VPNSession),
		ipToSession:  make(map[string]*VPNSession),
		vpnNetwork:   vpnNetwork,
		clientIPPool: NewIPPool(vpnNetwork, &config),
		config:       config,
		serverIP:     vpnNetwork.IP.To4(),
		natRules:     make([]NATRule, 0),
	}, nil
}

// InitializeTUN 初始化TUN设备
func (s *VPNServer) InitializeTUN() error {
	// 检查root权限
	if err := checkRootPrivileges(); err != nil {
		return err
	}

	// 创建TUN设备（自动选择可用名称，传入网络配置）
	tun, err := createTUNDevice("tun", s.config.Network)
	if err != nil {
		return err
	}
	s.tunDevice = tun
	log.Printf("服务器使用TUN设备: %s", tun.Name())

	// 配置TUN设备 - 服务器使用10.8.0.1/24
	serverIP := net.IPv4(s.serverIP[0], s.serverIP[1], s.serverIP[2], 1)
	s.serverIP = serverIP
	ipAddr := fmt.Sprintf("%s/24", serverIP.String())

	if err := configureTUNDevice(tun.Name(), ipAddr, s.config.MTU); err != nil {
		tun.Close()
		cleanupTUNDevice(tun.Name())
		return err
	}

	// 启用IP转发
	if err := enableIPForwarding(); err != nil {
		tun.Close()
		cleanupTUNDevice(tun.Name())
		return err
	}

	log.Printf("服务器TUN设备已初始化: %s (IP: %s)", tun.Name(), serverIP.String())
	return nil
}

// Start 启动VPN服务器（接受 context 控制生命周期）
func (s *VPNServer) Start(ctx context.Context) {
	log.Printf("VPN服务器启动，监听地址: %s", s.listener.Addr())

	// 创建内部 context
	ctx, cancel := context.WithCancel(ctx)
	s.cancelMutex.Lock()
	s.cancel = cancel
	s.cancelMutex.Unlock()

	// 使用 sync.Once 确保 listener 只关闭一次
	var closeOnce sync.Once
	closeListener := func() {
		closeOnce.Do(func() {
			s.listener.Close()
		})
	}

	defer func() {
		s.cancelMutex.Lock()
		s.cancel = nil
		s.cancelMutex.Unlock()
		closeListener()
	}()

	// 如果有TUN设备，启动TUN数据转发
	if s.tunDevice != nil {
		go s.handleTUNRead(ctx)
	}

	// 启动会话清理协程
	go s.cleanupSessions(ctx)

	// 监听 context 取消，关闭 listener 以中断 Accept
	go func() {
		<-ctx.Done()
		closeListener()
	}()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break // context 已取消
			}
			log.Printf("接受连接失败: %v", err)
			continue
		}

		go s.handleConnection(ctx, conn)
	}

	log.Println("VPN服务器已停止")
}

// handleConnection 处理连接
func (s *VPNServer) handleConnection(ctx context.Context, conn net.Conn) {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		log.Printf("非TLS连接被拒绝: %s", conn.RemoteAddr())
		conn.Close()
		return
	}

	err := tlsConn.Handshake()
	if err != nil {
		log.Printf("TLS握手失败: %v", err)
		conn.Close()
		return
	}

	// 验证客户端证书
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		log.Printf("客户端未提供证书: %s", conn.RemoteAddr())
		conn.Close()
		return
	}

	// 检查连接数限制
	s.sessionMutex.RLock()
	count := s.sessionCount
	s.sessionMutex.RUnlock()
	if count >= int64(s.config.MaxConnections) {
		log.Printf("连接数已达到上限: %d", s.config.MaxConnections)
		conn.Close()
		return
	}

	// 获取证书主题
	clientCert := state.PeerCertificates[0]
	certSubject := clientCert.Subject.CommonName

	// 分配IP地址
	clientIP := s.clientIPPool.AllocateIP()
	if clientIP == nil {
		log.Printf("IP地址池已满: %s", conn.RemoteAddr())
		conn.Close()
		return
	}

	// 生成唯一的SessionID (使用纳秒时间戳 + 随机数)
	sessionID := fmt.Sprintf("%s-%d-%d",
		conn.RemoteAddr().String(),
		time.Now().UnixNano(),
		mathrand.Int31())
	session := &VPNSession{
		ID:            sessionID,
		RemoteAddr:    conn.RemoteAddr(),
		TLSConn:       tlsConn,
		LastActivity:  time.Now(),
		IP:            clientIP,
		CertSubject:   certSubject,
		sendSeq:       0,
		recvSeq:       0,
		BytesSent:     0,
		BytesReceived: 0,
		ConnectedAt:   time.Now(),
	}

	s.addSession(sessionID, session)
	log.Printf("客户端连接建立: %s (IP: %s, Cert: %s, ID: %s)",
		conn.RemoteAddr(), clientIP, certSubject, sessionID)

	// 发送IP分配信息
	ipMsg := &Message{
		Type:     MessageTypeIPAssignment,
		Length:   uint32(len(clientIP)),
		Sequence: 0,
		Checksum: 0,
		Payload:  clientIP,
	}
	ipData, err := ipMsg.Serialize()
	if err != nil {
		log.Printf("序列化IP分配消息失败: %v", err)
		s.removeSession(sessionID)
		return
	}

	_, err = tlsConn.Write(ipData)
	if err != nil {
		log.Printf("发送IP分配信息失败: %v", err)
		s.removeSession(sessionID)
		return
	}

	// 推送配置给客户端（路由模式、DNS等）
	if err := s.pushConfigToClient(session); err != nil {
		log.Printf("推送配置给客户端失败: %v", err)
	}

	// 启动数据处理协程
	go s.handleSessionData(ctx, session)
}

// handleSessionData 处理会话数据
func (s *VPNServer) handleSessionData(ctx context.Context, session *VPNSession) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("会话 %s 处理发生panic: %v", session.ID, r)
		}
		s.removeSession(session.ID)
		log.Printf("会话 %s 已清理，IP %s 已回收", session.ID, session.IP)
	}()

sessionLoop:
	for !session.IsClosed() {
		// 检查 context 是否取消
		select {
		case <-ctx.Done():
			break sessionLoop
		default:
		}

		session.TLSConn.SetReadDeadline(time.Now().Add(30 * time.Second))

		// 读取消息头（13字节：类型+长度+序列号+校验和）
		header := make([]byte, 13)
		_, err := io.ReadFull(session.TLSConn, header)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// 检查是否超时
				if time.Since(session.GetActivity()) > 90*time.Second {
					log.Printf("会话超时: %s", session.ID)
					break
				}
				continue // 继续等待数据
			}
			if err != io.EOF {
				log.Printf("会话 %s 读取消息头失败: %v", session.ID, err)
			}
			break
		}

		// 解析消息头
		msgType := MessageType(header[0])
		length := binary.BigEndian.Uint32(header[1:5])
		sequence := binary.BigEndian.Uint32(header[5:9])
		checksum := binary.BigEndian.Uint32(header[9:13])

		// 防止过大的消息
		if length > 65535 {
			log.Printf("会话 %s 消息过大: %d 字节", session.ID, length)
			break
		}

		// 读取消息体
		payload := make([]byte, length)
		if length > 0 {
			_, err = io.ReadFull(session.TLSConn, payload)
			if err != nil {
				log.Printf("会话 %s 读取消息体失败: %v", session.ID, err)
				break
			}
		}

		// 验证序列号（心跳消息除外）
		if msgType != MessageTypeHeartbeat && msgType != MessageTypeIPAssignment {
			session.seqMutex.Lock()
			// 检测重放攻击（序列号回退）
			if sequence < session.recvSeq {
				session.seqMutex.Unlock()
				log.Printf("会话 %s 检测到重放攻击：期望序列号 >= %d，收到 %d",
					session.ID, session.recvSeq, sequence)
				break
			}
			// 检测消息丢失（序列号跳跃）
			if sequence > session.recvSeq+1 && session.recvSeq > 0 {
				log.Printf("警告：会话 %s 检测到消息丢失，期望序列号 %d，收到 %d",
					session.ID, session.recvSeq+1, sequence)
			}
			session.recvSeq = sequence
			session.seqMutex.Unlock()
		}

		// 验证校验和（如果提供）
		if checksum != 0 && len(payload) > 0 {
			actualChecksum := crc32.ChecksumIEEE(payload)
			if actualChecksum != checksum {
				log.Printf("会话 %s 消息校验和不匹配: 期望 %d, 收到 %d",
					session.ID, actualChecksum, checksum)
				break
			}
		}

		session.UpdateActivity()

		// 处理不同类型的消息
		switch msgType {
		case MessageTypeHeartbeat:
			// 响应心跳
			if err := s.sendHeartbeatResponse(session); err != nil {
				log.Printf("会话 %s 发送心跳响应失败: %v", session.ID, err)
				break sessionLoop
			}
		case MessageTypeData:
			// 统计接收流量
			session.AddBytesReceived(uint64(len(payload)))

			// 处理数据包 - 直接写入TUN设备（Windows Wintun和Unix/Linux TUN都是Layer 3）
			if s.tunDevice != nil && len(payload) > 0 {
				_, err := s.tunDevice.Write(payload)
				if err != nil {
					log.Printf("会话 %s 写入TUN设备失败: %v", session.ID, err)
				}
			} else {
				log.Printf("从会话 %s 接收到数据包，长度: %d", session.ID, len(payload))
			}
		default:
			log.Printf("会话 %s 收到未知消息类型: %d", session.ID, msgType)
		}
	}

	log.Printf("会话断开: %s", session.ID)
}

// sendHeartbeatResponse 发送心跳响应
func (s *VPNServer) sendHeartbeatResponse(session *VPNSession) error {
	response := &Message{
		Type:     MessageTypeHeartbeat,
		Length:   0,
		Sequence: 0, // 心跳不使用序列号
		Checksum: 0,
		Payload:  []byte{},
	}
	responseData, err := response.Serialize()
	if err != nil {
		return fmt.Errorf("序列化心跳响应失败: %v", err)
	}
	_, err = session.TLSConn.Write(responseData)
	return err
}

// sendDataResponse 发送数据响应
func (s *VPNServer) sendDataResponse(session *VPNSession, payload []byte) error {
	// 获取并递增发送序列号
	session.seqMutex.Lock()
	seq := session.sendSeq
	session.sendSeq++
	session.seqMutex.Unlock()

	// 计算校验和（可选）
	checksum := uint32(0)
	if len(payload) > 0 {
		checksum = crc32.ChecksumIEEE(payload)
	}

	response := &Message{
		Type:     MessageTypeData,
		Length:   uint32(len(payload)),
		Sequence: seq,
		Checksum: checksum,
		Payload:  payload,
	}
	responseData, err := response.Serialize()
	if err != nil {
		return fmt.Errorf("序列化数据响应失败: %v", err)
	}
	_, err = session.TLSConn.Write(responseData)
	if err == nil {
		// 统计发送流量
		session.AddBytesSent(uint64(len(payload)))
	}
	return err
}

// pushConfigToClient 推送配置给客户端
func (s *VPNServer) pushConfigToClient(session *VPNSession) error {
	// 准备客户端配置
	config := ClientConfig{
		AssignedIP:      session.IP.String() + "/24",
		ServerIP:        s.config.ServerIP,
		DNS:             s.config.DNSServers,
		Routes:          s.config.PushRoutes,
		MTU:             s.config.MTU,
		RouteMode:       s.config.RouteMode,
		ExcludeRoutes:   s.config.ExcludeRoutes,
		RedirectGateway: s.config.RedirectGateway,
		RedirectDNS:     s.config.RedirectDNS,
	}

	// 序列化为JSON
	data, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("序列化客户端配置失败: %v", err)
	}

	// 获取并递增发送序列号
	session.seqMutex.Lock()
	seq := session.sendSeq
	session.sendSeq++
	session.seqMutex.Unlock()

	// 发送控制消息
	msg := &Message{
		Type:     MessageTypeControl,
		Length:   uint32(len(data)),
		Sequence: seq,
		Checksum: crc32.ChecksumIEEE(data),
		Payload:  data,
	}

	msgData, err := msg.Serialize()
	if err != nil {
		return fmt.Errorf("序列化控制消息失败: %v", err)
	}

	_, err = session.TLSConn.Write(msgData)
	if err != nil {
		return fmt.Errorf("发送配置失败: %v", err)
	}

	log.Printf("已推送配置给客户端 %s: DNS=%v, Routes=%v, MTU=%d",
		session.IP, config.DNS, config.Routes, config.MTU)
	return nil
}

// handleTUNRead 处理从TUN设备读取的数据
func (s *VPNServer) handleTUNRead(ctx context.Context) {
	packet := make([]byte, s.config.MTU)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := s.tunDevice.Read(packet)
		if err != nil {
			if ctx.Err() == nil {
				log.Printf("从TUN设备读取失败: %v", err)
			}
			return
		}

		if n < 20 { // IP header minimum size
			continue
		}

		// 提取目标IP地址 (IP header offset 16-19)
		destIP := net.IP(packet[16:20])

		// 使用IP到会话的映射进行O(1)查找
		s.sessionMutex.RLock()
		targetSession := s.ipToSession[destIP.String()]
		s.sessionMutex.RUnlock()

		if targetSession != nil {
			// 发送到目标客户端
			err := s.sendDataResponse(targetSession, packet[:n])
			if err != nil {
				log.Printf("转发数据包到客户端 %s 失败: %v", destIP, err)
			}
		}
	}
}

// addSession 添加会话
func (s *VPNServer) addSession(id string, session *VPNSession) {
	s.sessionMutex.Lock()
	defer s.sessionMutex.Unlock()
	s.sessions[id] = session
	s.ipToSession[session.IP.String()] = session // 维护IP到会话的映射
	s.sessionCount++
}

// removeSession 移除会话
func (s *VPNServer) removeSession(id string) {
	s.sessionMutex.Lock()
	session, exists := s.sessions[id]
	if exists {
		s.clientIPPool.ReleaseIP(session.IP)
		delete(s.sessions, id)
		delete(s.ipToSession, session.IP.String()) // 删除IP映射
		s.sessionCount--
	}
	s.sessionMutex.Unlock()

	// 在锁外部关闭连接，避免死锁
	if exists && session != nil {
		_ = session.Close()
	}
}

// cleanupSessions 清理会话
func (s *VPNServer) cleanupSessions(ctx context.Context) {
	ticker := time.NewTicker(s.config.SessionCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// 收集需要清理的会话ID
			var toCleanup []string
			s.sessionMutex.RLock()
			for id, session := range s.sessions {
				if time.Since(session.GetActivity()) > s.config.SessionTimeout {
					toCleanup = append(toCleanup, id)
				}
			}
			s.sessionMutex.RUnlock()

			// 释放锁后再清理会话
			for _, id := range toCleanup {
				log.Printf("清理超时会话: %s", id)
				s.removeSession(id)
			}
		}
	}
}

// cleanupNATRules 清理NAT规则
func (s *VPNServer) cleanupNATRules() {
	// 加锁复制规则列表，避免并发访问
	s.sessionMutex.Lock()
	rules := make([]NATRule, len(s.natRules))
	copy(rules, s.natRules)
	s.natRules = nil
	s.sessionMutex.Unlock()

	// 在锁外执行清理操作
	for _, rule := range rules {
		// 将 -A 改为 -D 来删除规则
		args := []string{"-t", rule.Table, "-D", rule.Chain}
		args = append(args, rule.Args...)

		output, err := runCmdCombined("iptables", args...)
		if err != nil {
			log.Printf("警告：删除NAT规则失败: %v (参数: %v), 输出: %s", err, args, string(output))
		} else {
			log.Printf("已删除NAT规则: %v", args)
		}
	}
}

// Stop 停止服务器
func (s *VPNServer) Stop() {
	// 取消 context，停止所有协程
	s.cancelMutex.Lock()
	if s.cancel != nil {
		s.cancel()
	}
	s.cancelMutex.Unlock()

	// 关闭 listener
	if s.listener != nil {
		_ = s.listener.Close()
	}

	// 收集所有会话ID
	s.sessionMutex.Lock()
	sessionIDs := make([]string, 0, len(s.sessions))
	for id := range s.sessions {
		sessionIDs = append(sessionIDs, id)
	}
	s.sessionMutex.Unlock()

	// 在锁外部关闭所有会话
	for _, id := range sessionIDs {
		s.removeSession(id)
	}

	// 清理NAT规则
	s.cleanupNATRules()

	// 清理TUN设备
	if s.tunDevice != nil {
		deviceName := s.tunDevice.Name()
		_ = s.tunDevice.Close()
		cleanupTUNDevice(deviceName)
	}
}

// IsRunning 检查服务器是否运行中
func (s *VPNServer) IsRunning() bool {
	s.cancelMutex.Lock()
	defer s.cancelMutex.Unlock()
	return s.cancel != nil
}

// GetSessionCount 获取在线会话数
func (s *VPNServer) GetSessionCount() int {
	s.sessionMutex.RLock()
	defer s.sessionMutex.RUnlock()
	return len(s.sessions)
}

// SessionInfo 会话信息（用于显示）
type SessionInfo struct {
	ID            string
	IP            string
	RemoteAddr    string
	CertSubject   string
	ConnectedAt   time.Time
	LastActivity  time.Time
	BytesSent     uint64
	BytesReceived uint64
}

// GetAllSessions 获取所有会话信息
func (s *VPNServer) GetAllSessions() []SessionInfo {
	s.sessionMutex.RLock()
	defer s.sessionMutex.RUnlock()

	sessions := make([]SessionInfo, 0, len(s.sessions))
	for _, session := range s.sessions {
		sent, received, _ := session.GetStats()
		sessions = append(sessions, SessionInfo{
			ID:            session.ID,
			IP:            session.IP.String(),
			RemoteAddr:    session.RemoteAddr.String(),
			CertSubject:   session.CertSubject,
			ConnectedAt:   session.ConnectedAt,
			LastActivity:  session.GetActivity(),
			BytesSent:     sent,
			BytesReceived: received,
		})
	}

	// 按连接时间排序
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].ConnectedAt.Before(sessions[j].ConnectedAt)
	})

	return sessions
}

// KickSession 踢出指定会话
func (s *VPNServer) KickSession(sessionID string) bool {
	s.sessionMutex.RLock()
	_, exists := s.sessions[sessionID]
	s.sessionMutex.RUnlock()

	if !exists {
		return false
	}

	s.removeSession(sessionID)
	return true
}

// KickByIP 根据IP踢出会话
func (s *VPNServer) KickByIP(ip string) bool {
	s.sessionMutex.RLock()
	session := s.ipToSession[ip]
	s.sessionMutex.RUnlock()

	if session == nil {
		return false
	}

	s.removeSession(session.ID)
	return true
}

// GetTotalStats 获取总流量统计
func (s *VPNServer) GetTotalStats() (totalSent, totalReceived uint64) {
	s.sessionMutex.RLock()
	defer s.sessionMutex.RUnlock()

	for _, session := range s.sessions {
		sent, received, _ := session.GetStats()
		totalSent += sent
		totalReceived += received
	}
	return
}

// GetTUNDeviceName 获取TUN设备名称
func (s *VPNServer) GetTUNDeviceName() string {
	if s.tunDevice != nil {
		return s.tunDevice.Name()
	}
	return ""
}
