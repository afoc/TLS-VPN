package main

import (
	"encoding/binary"
	"fmt"
)

// MessageType 消息类型枚举
type MessageType uint8

const (
	MessageTypeData MessageType = iota
	MessageTypeHeartbeat
	MessageTypeIPAssignment
	MessageTypeAuth
	MessageTypeControl
)

// Message VPN消息结构
type Message struct {
	Type     MessageType
	Length   uint32
	Sequence uint32 // 新增：消息序列号
	Checksum uint32 // 新增：CRC32校验和（可选，0表示不校验）
	Payload  []byte
}

// Serialize 序列化消息
func (m *Message) Serialize() ([]byte, error) {
	// 新格式: Type(1) + Length(4) + Sequence(4) + Checksum(4) + Payload
	header := make([]byte, 13)
	header[0] = byte(m.Type)
	binary.BigEndian.PutUint32(header[1:5], m.Length)
	binary.BigEndian.PutUint32(header[5:9], m.Sequence)
	binary.BigEndian.PutUint32(header[9:13], m.Checksum)

	return append(header, m.Payload...), nil
}

// Deserialize 反序列化消息
func Deserialize(data []byte) (*Message, error) {
	if len(data) < 13 {
		return nil, fmt.Errorf("消息长度不足")
	}

	msgType := MessageType(data[0])
	length := binary.BigEndian.Uint32(data[1:5])
	sequence := binary.BigEndian.Uint32(data[5:9])
	checksum := binary.BigEndian.Uint32(data[9:13])

	if uint32(len(data)) < 13+length {
		return nil, fmt.Errorf("消息长度不匹配")
	}

	payload := data[13 : 13+length]
	return &Message{
		Type:     msgType,
		Length:   length,
		Sequence: sequence,
		Checksum: checksum,
		Payload:  payload,
	}, nil
}

// ClientConfig 客户端配置（服务端推送给客户端）
type ClientConfig struct {
	AssignedIP      string   `json:"assigned_ip"`      // 分配的IP地址（例如 "10.8.0.2/24"）
	ServerIP        string   `json:"server_ip"`        // 服务器IP地址
	DNS             []string `json:"dns"`              // DNS服务器列表
	Routes          []string `json:"routes"`           // 路由列表（CIDR格式）
	MTU             int      `json:"mtu"`              // MTU大小
	RouteMode       string   `json:"route_mode"`       // 路由模式 "full" 或 "split"
	ExcludeRoutes   []string `json:"exclude_routes"`   // 排除的路由（full模式使用）
	RedirectGateway bool     `json:"redirect_gateway"` // 是否重定向默认网关
	RedirectDNS     bool     `json:"redirect_dns"`     // 是否劫持DNS
}
