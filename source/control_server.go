package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
)

// ControlServer 控制 API 服务端（Unix Socket）
type ControlServer struct {
	socketPath string
	listener   net.Listener
	service    *VPNService
	running    bool
	mu         sync.Mutex
	done       chan struct{}
}

// NewControlServer 创建控制服务端
func NewControlServer(service *VPNService) *ControlServer {
	return &ControlServer{
		socketPath: ControlSocketPath,
		service:    service,
		done:       make(chan struct{}),
	}
}

// Start 启动控制服务端
func (s *ControlServer) Start() error {
	// 清理旧的 socket 文件
	os.Remove(s.socketPath)

	listener, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("监听失败: %v", err)
	}

	// 设置权限（允许同组用户访问）
	os.Chmod(s.socketPath, 0660)

	s.mu.Lock()
	s.listener = listener
	s.running = true
	s.mu.Unlock()

	log.Printf("控制API服务已启动: %s", s.socketPath)

	go s.acceptLoop()
	return nil
}

// Stop 停止控制服务端
func (s *ControlServer) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	s.mu.Unlock()

	close(s.done)
	if s.listener != nil {
		s.listener.Close()
	}
	os.Remove(s.socketPath)
	log.Println("控制API服务已停止")
}

func (s *ControlServer) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				log.Printf("接受连接失败: %v", err)
				continue
			}
		}
		go s.handleConnection(conn)
	}
}

func (s *ControlServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return
	}

	var req APIRequest
	if err := json.Unmarshal(line, &req); err != nil {
		s.sendError(conn, "无效的请求格式")
		return
	}

	resp := s.handleRequest(req)
	s.sendResponse(conn, resp)
}

func (s *ControlServer) handleRequest(req APIRequest) APIResponse {
	switch req.Action {
	// 服务端
	case ActionServerStart:
		return s.handleServerStart()
	case ActionServerStop:
		return s.handleServerStop()
	case ActionServerStatus:
		return s.handleServerStatus()
	case ActionServerClients:
		return s.handleServerClients()
	case ActionServerKick:
		return s.handleServerKick(req.Data)
	case ActionServerStats:
		return s.handleServerStats()

	// 客户端
	case ActionClientConnect:
		return s.handleClientConnect()
	case ActionClientDisconnect:
		return s.handleClientDisconnect()
	case ActionClientStatus:
		return s.handleClientStatus()

	// 证书
	case ActionCertInitCA:
		return s.handleCertInitCA()
	case ActionCertList:
		return s.handleCertList()
	case ActionCertClients:
		return s.handleCertClients()
	case ActionCertGenCSR:
		return s.handleCertGenCSR(req.Data)
	case ActionCertRequest:
		return s.handleCertRequest(req.Data)
	case ActionCertStatus:
		return s.handleCertStatus()

	// Token
	case ActionTokenGenerate:
		return s.handleTokenGenerate(req.Data)
	case ActionTokenList:
		return s.handleTokenList()
	case ActionTokenDelete:
		return s.handleTokenDelete(req.Data)
	case ActionTokenCleanup:
		return s.handleTokenCleanup()

	// 配置
	case ActionConfigGet:
		return s.handleConfigGet()
	case ActionConfigUpdate:
		return s.handleConfigUpdate(req.Data)
	case ActionConfigSave:
		return s.handleConfigSave()
	case ActionConfigLoad:
		return s.handleConfigLoad()
	case ActionConfigReset:
		return s.handleConfigReset()

	// 日志
	case ActionLogFetch:
		return s.handleLogFetch(req.Data)

	// 系统
	case ActionPing:
		return APIResponse{Success: true, Message: "pong"}
	case ActionShutdown:
		return s.handleShutdown()

	default:
		return APIResponse{Success: false, Error: "未知的操作: " + req.Action}
	}
}

// ================ 服务端处理 ================

func (s *ControlServer) handleServerStart() APIResponse {
	if err := s.service.StartServer(); err != nil {
		return APIResponse{Success: false, Error: err.Error()}
	}
	status := s.service.GetServerStatus()
	return APIResponse{
		Success: true,
		Message: fmt.Sprintf("服务端已启动 (端口: %d, TUN: %s)", status.Port, status.TUNDevice),
	}
}

func (s *ControlServer) handleServerStop() APIResponse {
	if err := s.service.StopServer(); err != nil {
		return APIResponse{Success: false, Error: err.Error()}
	}
	return APIResponse{Success: true, Message: "服务端已停止"}
}

func (s *ControlServer) handleServerStatus() APIResponse {
	status := s.service.GetServerStatus()
	data, _ := json.Marshal(status)
	return APIResponse{Success: true, Data: data}
}

func (s *ControlServer) handleServerClients() APIResponse {
	clients := s.service.GetOnlineClients()
	data, _ := json.Marshal(ClientListResponse{Clients: clients})
	return APIResponse{Success: true, Data: data}
}

func (s *ControlServer) handleServerKick(reqData json.RawMessage) APIResponse {
	var req KickClientRequest
	if err := json.Unmarshal(reqData, &req); err != nil {
		return APIResponse{Success: false, Error: "无效的请求数据"}
	}
	if err := s.service.KickClient(req.IP); err != nil {
		return APIResponse{Success: false, Error: err.Error()}
	}
	return APIResponse{Success: true, Message: "已踢出客户端: " + req.IP}
}

func (s *ControlServer) handleServerStats() APIResponse {
	status := s.service.GetServerStatus()
	clients := s.service.GetOnlineClients()

	type StatsResponse struct {
		TotalSent   uint64       `json:"total_sent"`
		TotalRecv   uint64       `json:"total_recv"`
		ClientCount int          `json:"client_count"`
		Clients     []ClientInfo `json:"clients"`
	}
	resp := StatsResponse{
		TotalSent:   status.TotalSent,
		TotalRecv:   status.TotalRecv,
		ClientCount: len(clients),
		Clients:     clients,
	}
	data, _ := json.Marshal(resp)
	return APIResponse{Success: true, Data: data}
}

// ================ 客户端处理 ================

func (s *ControlServer) handleClientConnect() APIResponse {
	if err := s.service.ConnectClient(); err != nil {
		return APIResponse{Success: false, Error: err.Error()}
	}
	return APIResponse{Success: true, Message: "客户端已启动连接"}
}

func (s *ControlServer) handleClientDisconnect() APIResponse {
	if err := s.service.DisconnectClient(); err != nil {
		return APIResponse{Success: false, Error: err.Error()}
	}
	return APIResponse{Success: true, Message: "已断开VPN连接"}
}

func (s *ControlServer) handleClientStatus() APIResponse {
	status := s.service.GetClientStatus()
	data, _ := json.Marshal(status)
	return APIResponse{Success: true, Data: data}
}

// ================ 证书处理 ================

func (s *ControlServer) handleCertInitCA() APIResponse {
	if err := s.service.InitCA(); err != nil {
		return APIResponse{Success: false, Error: err.Error()}
	}
	return APIResponse{Success: true, Message: "CA证书已生成"}
}

func (s *ControlServer) handleCertList() APIResponse {
	list := s.service.GetCertList()
	data, _ := json.Marshal(list)
	return APIResponse{Success: true, Data: data}
}

func (s *ControlServer) handleCertClients() APIResponse {
	clients := s.service.GetSignedClients()
	data, _ := json.Marshal(SignedClientsResponse{Clients: clients})
	return APIResponse{Success: true, Data: data}
}

func (s *ControlServer) handleCertGenCSR(reqData json.RawMessage) APIResponse {
	var req GenerateCSRRequest
	if err := json.Unmarshal(reqData, &req); err != nil {
		return APIResponse{Success: false, Error: "无效的请求数据"}
	}
	resp, err := s.service.GenerateCSR(req.ClientName)
	if err != nil {
		return APIResponse{Success: false, Error: err.Error()}
	}
	data, _ := json.Marshal(resp)
	return APIResponse{Success: true, Message: "CSR已生成", Data: data}
}

func (s *ControlServer) handleCertRequest(reqData json.RawMessage) APIResponse {
	var req RequestCertRequest
	if err := json.Unmarshal(reqData, &req); err != nil {
		return APIResponse{Success: false, Error: "无效的请求数据"}
	}
	if err := s.service.RequestCert(req); err != nil {
		return APIResponse{Success: false, Error: err.Error()}
	}
	return APIResponse{Success: true, Message: "证书申请成功，已自动部署"}
}

func (s *ControlServer) handleCertStatus() APIResponse {
	exists := s.service.CertificatesExistCheck()
	type StatusResp struct {
		Exists bool `json:"exists"`
	}
	data, _ := json.Marshal(StatusResp{Exists: exists})
	return APIResponse{Success: true, Data: data}
}

// ================ Token 处理 ================

func (s *ControlServer) handleTokenGenerate(reqData json.RawMessage) APIResponse {
	var req GenerateTokenRequest
	if err := json.Unmarshal(reqData, &req); err != nil {
		return APIResponse{Success: false, Error: "无效的请求数据"}
	}
	resp, err := s.service.GenerateToken(req.ClientName, req.Duration)
	if err != nil {
		return APIResponse{Success: false, Error: err.Error()}
	}
	data, _ := json.Marshal(resp)
	return APIResponse{Success: true, Message: "Token已生成", Data: data}
}

func (s *ControlServer) handleTokenList() APIResponse {
	tokens := s.service.GetTokenList()
	data, _ := json.Marshal(TokenListResponse{Tokens: tokens})
	return APIResponse{Success: true, Data: data}
}

func (s *ControlServer) handleTokenDelete(reqData json.RawMessage) APIResponse {
	var req DeleteTokenRequest
	if err := json.Unmarshal(reqData, &req); err != nil {
		return APIResponse{Success: false, Error: "无效的请求数据"}
	}
	if err := s.service.DeleteToken(req.Index); err != nil {
		return APIResponse{Success: false, Error: err.Error()}
	}
	return APIResponse{Success: true, Message: "Token已删除"}
}

func (s *ControlServer) handleTokenCleanup() APIResponse {
	count := s.service.CleanupExpiredTokens()
	return APIResponse{Success: true, Message: fmt.Sprintf("已清理 %d 个过期Token", count)}
}

// ================ 配置处理 ================

func (s *ControlServer) handleConfigGet() APIResponse {
	cfg := s.service.GetConfig()
	data, _ := json.Marshal(ConfigResponse{Config: cfg})
	return APIResponse{Success: true, Data: data}
}

func (s *ControlServer) handleConfigUpdate(reqData json.RawMessage) APIResponse {
	var req UpdateConfigRequest
	if err := json.Unmarshal(reqData, &req); err != nil {
		return APIResponse{Success: false, Error: "无效的请求数据"}
	}
	if err := s.service.UpdateConfig(req.Field, req.Value); err != nil {
		return APIResponse{Success: false, Error: err.Error()}
	}
	return APIResponse{Success: true, Message: "配置已更新"}
}

func (s *ControlServer) handleConfigSave() APIResponse {
	if err := s.service.SaveConfig(); err != nil {
		return APIResponse{Success: false, Error: err.Error()}
	}
	return APIResponse{Success: true, Message: "配置已保存"}
}

func (s *ControlServer) handleConfigLoad() APIResponse {
	if err := s.service.LoadConfig(); err != nil {
		return APIResponse{Success: false, Error: err.Error()}
	}
	return APIResponse{Success: true, Message: "配置已加载"}
}

func (s *ControlServer) handleConfigReset() APIResponse {
	s.service.ResetConfig()
	return APIResponse{Success: true, Message: "已恢复默认配置"}
}

// ================ 日志处理 ================

func (s *ControlServer) handleLogFetch(reqData json.RawMessage) APIResponse {
	var req LogFetchRequest
	if reqData != nil {
		json.Unmarshal(reqData, &req)
	}

	logger := GetServiceLogger()
	if logger == nil {
		return APIResponse{Success: false, Error: "日志系统未初始化"}
	}

	limit := req.Limit
	if limit <= 0 {
		limit = 100 // 默认最多返回 100 条
	}

	logs, lastSeq := logger.GetLogsSince(req.Since, limit)

	resp := LogFetchResponse{
		Logs:    logs,
		LastSeq: lastSeq,
	}
	data, _ := json.Marshal(resp)
	return APIResponse{Success: true, Data: data}
}

// ================ 系统处理 ================

func (s *ControlServer) handleShutdown() APIResponse {
	go func() {
		s.service.Cleanup()
		s.Stop()
		os.Exit(0)
	}()
	return APIResponse{Success: true, Message: "服务正在关闭..."}
}

// ================ 辅助方法 ================

func (s *ControlServer) sendResponse(conn net.Conn, resp APIResponse) {
	data, _ := json.Marshal(resp)
	conn.Write(append(data, '\n'))
}

func (s *ControlServer) sendError(conn net.Conn, msg string) {
	s.sendResponse(conn, APIResponse{Success: false, Error: msg})
}
