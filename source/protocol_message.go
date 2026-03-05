package main

import (
	"encoding/binary"
	"fmt"
	"io"
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
	Type    MessageType
	Length  uint32
	Payload []byte
}

const (
	SimpleHeaderSize = 5
	MaxMessageLength = 65535
)

// Serialize 序列化消息
func (m *Message) Serialize() ([]byte, error) {
	if m.Length != uint32(len(m.Payload)) {
		m.Length = uint32(len(m.Payload))
	}

	header := make([]byte, SimpleHeaderSize)
	header[0] = byte(m.Type)
	binary.BigEndian.PutUint32(header[1:5], m.Length)
	return append(header, m.Payload...), nil
}

// Deserialize 反序列化消息
func Deserialize(data []byte) (*Message, error) {
	if len(data) < SimpleHeaderSize {
		return nil, fmt.Errorf("消息长度不足")
	}

	msgType := MessageType(data[0])
	length := binary.BigEndian.Uint32(data[1:5])

	if uint32(len(data)) < SimpleHeaderSize+length {
		return nil, fmt.Errorf("消息长度不匹配")
	}

	payload := data[SimpleHeaderSize : SimpleHeaderSize+length]
	return &Message{
		Type:    msgType,
		Length:  length,
		Payload: payload,
	}, nil
}

func ReadMessage(reader io.Reader) (*Message, error) {
	baseHeader := make([]byte, SimpleHeaderSize)
	if _, err := io.ReadFull(reader, baseHeader); err != nil {
		return nil, err
	}

	msgType := MessageType(baseHeader[0])
	length := binary.BigEndian.Uint32(baseHeader[1:5])
	if length > MaxMessageLength {
		return nil, fmt.Errorf("消息过大: %d", length)
	}

	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(reader, payload); err != nil {
			return nil, err
		}
	}

	return &Message{
		Type:    msgType,
		Length:  length,
		Payload: payload,
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
