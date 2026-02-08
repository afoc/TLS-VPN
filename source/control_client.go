package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// ControlClient 控制 API 客户端
type ControlClient struct {
	socketPath string
	timeout    time.Duration
}

// NewControlClient 创建控制客户端
func NewControlClient() *ControlClient {
	return &ControlClient{
		socketPath: ControlSocketPath,
		timeout:    30 * time.Second,
	}
}

// Call 调用 API
func (c *ControlClient) Call(action string, data interface{}) (*APIResponse, error) {
	conn, err := net.DialTimeout("unix", c.socketPath, c.timeout)
	if err != nil {
		return nil, fmt.Errorf("连接服务失败: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(c.timeout))

	// 构造请求
	req := APIRequest{Action: action}
	if data != nil {
		req.Data, _ = json.Marshal(data)
	}

	// 发送请求
	reqData, _ := json.Marshal(req)
	if _, err := conn.Write(append(reqData, '\n')); err != nil {
		return nil, fmt.Errorf("发送请求失败: %v", err)
	}

	// 读取响应
	reader := bufio.NewReader(conn)
	respData, err := reader.ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %v", err)
	}

	var resp APIResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		return nil, fmt.Errorf("解析响应失败: %v", err)
	}

	return &resp, nil
}

// IsServiceRunning 检查服务是否运行
func (c *ControlClient) IsServiceRunning() bool {
	resp, err := c.Call(ActionPing, nil)
	return err == nil && resp.Success
}

// ================ 便捷方法 ================

// ServerStart 启动服务端
func (c *ControlClient) ServerStart() (*APIResponse, error) {
	return c.Call(ActionServerStart, nil)
}

// ServerStop 停止服务端
func (c *ControlClient) ServerStop() (*APIResponse, error) {
	return c.Call(ActionServerStop, nil)
}

// ServerStatus 获取服务端状态
func (c *ControlClient) ServerStatus() (*ServerStatusResponse, error) {
	resp, err := c.Call(ActionServerStatus, nil)
	if err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("%s", resp.Error)
	}
	var status ServerStatusResponse
	if err := json.Unmarshal(resp.Data, &status); err != nil {
		return nil, fmt.Errorf("解析状态失败: %v", err)
	}
	return &status, nil
}

// ServerClients 获取在线客户端
func (c *ControlClient) ServerClients() ([]ClientInfo, error) {
	resp, err := c.Call(ActionServerClients, nil)
	if err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("%s", resp.Error)
	}
	var result ClientListResponse
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("解析客户端列表失败: %v", err)
	}
	return result.Clients, nil
}

// ServerKick 踢出客户端
func (c *ControlClient) ServerKick(ip string) (*APIResponse, error) {
	return c.Call(ActionServerKick, KickClientRequest{IP: ip})
}

// ClientConnect 连接 VPN
func (c *ControlClient) ClientConnect() (*APIResponse, error) {
	return c.Call(ActionClientConnect, nil)
}

// ClientDisconnect 断开 VPN
func (c *ControlClient) ClientDisconnect() (*APIResponse, error) {
	return c.Call(ActionClientDisconnect, nil)
}

// ClientStatus 获取客户端状态
func (c *ControlClient) ClientStatus() (*VPNClientStatusResponse, error) {
	resp, err := c.Call(ActionClientStatus, nil)
	if err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("%s", resp.Error)
	}
	var status VPNClientStatusResponse
	if err := json.Unmarshal(resp.Data, &status); err != nil {
		return nil, fmt.Errorf("解析客户端状态失败: %v", err)
	}
	return &status, nil
}

// CertInitCA 初始化 CA
func (c *ControlClient) CertInitCA() (*APIResponse, error) {
	return c.Call(ActionCertInitCA, nil)
}

// CertList 获取证书列表
func (c *ControlClient) CertList() (*CertListResponse, error) {
	resp, err := c.Call(ActionCertList, nil)
	if err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("%s", resp.Error)
	}
	var result CertListResponse
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("解析证书列表失败: %v", err)
	}
	return &result, nil
}

// CertGenCSR 生成 CSR
func (c *ControlClient) CertGenCSR(clientName string) (*GenerateCSRResponse, error) {
	resp, err := c.Call(ActionCertGenCSR, GenerateCSRRequest{ClientName: clientName})
	if err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("%s", resp.Error)
	}
	var result GenerateCSRResponse
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("解析CSR响应失败: %v", err)
	}
	return &result, nil
}

// CertRequest 申请证书
func (c *ControlClient) CertRequest(req RequestCertRequest) (*APIResponse, error) {
	return c.Call(ActionCertRequest, req)
}

// TokenGenerate 生成 Token
func (c *ControlClient) TokenGenerate(clientName string, duration int) (*GenerateTokenResponse, error) {
	resp, err := c.Call(ActionTokenGenerate, GenerateTokenRequest{
		ClientName: clientName,
		Duration:   duration,
	})
	if err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("%s", resp.Error)
	}
	var result GenerateTokenResponse
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("解析Token响应失败: %v", err)
	}
	return &result, nil
}

// TokenList 获取 Token 列表
func (c *ControlClient) TokenList() ([]TokenInfo, error) {
	resp, err := c.Call(ActionTokenList, nil)
	if err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("%s", resp.Error)
	}
	var result TokenListResponse
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("解析Token列表失败: %v", err)
	}
	return result.Tokens, nil
}

// TokenDelete 删除 Token
func (c *ControlClient) TokenDelete(index int) (*APIResponse, error) {
	return c.Call(ActionTokenDelete, DeleteTokenRequest{Index: index})
}

// TokenCleanup 清理过期 Token
func (c *ControlClient) TokenCleanup() (*APIResponse, error) {
	return c.Call(ActionTokenCleanup, nil)
}

// ConfigGet 获取配置
func (c *ControlClient) ConfigGet() (*VPNConfig, error) {
	resp, err := c.Call(ActionConfigGet, nil)
	if err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("%s", resp.Error)
	}
	var result ConfigResponse
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("解析配置失败: %v", err)
	}
	return &result.Config, nil
}

// ConfigUpdate 更新配置
func (c *ControlClient) ConfigUpdate(field string, value interface{}) (*APIResponse, error) {
	return c.Call(ActionConfigUpdate, UpdateConfigRequest{Field: field, Value: value})
}

// ConfigSave 保存配置
func (c *ControlClient) ConfigSave() (*APIResponse, error) {
	return c.Call(ActionConfigSave, nil)
}

// ConfigLoad 加载配置
func (c *ControlClient) ConfigLoad() (*APIResponse, error) {
	return c.Call(ActionConfigLoad, nil)
}

// ConfigReset 重置配置
func (c *ControlClient) ConfigReset() (*APIResponse, error) {
	return c.Call(ActionConfigReset, nil)
}

// Shutdown 关闭服务
func (c *ControlClient) Shutdown() (*APIResponse, error) {
	return c.Call(ActionShutdown, nil)
}

// LogFetch 获取日志
func (c *ControlClient) LogFetch(since uint64, limit int) (*LogFetchResponse, error) {
	resp, err := c.Call(ActionLogFetch, LogFetchRequest{Since: since, Limit: limit})
	if err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("%s", resp.Error)
	}
	var result LogFetchResponse
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("解析日志响应失败: %v", err)
	}
	return &result, nil
}
