package main

// TUNDevice 统一的TUN设备接口（支持Linux和Windows）
// Linux使用water.Interface实现（自动满足此接口）
// Windows使用WintunAdapter实现
type TUNDevice interface {
	// Read 从TUN设备读取一个IP包
	Read(p []byte) (n int, err error)

	// Write 向TUN设备写入一个IP包
	Write(p []byte) (n int, err error)

	// Name 返回设备名称
	Name() string

	// Close 关闭设备
	Close() error
}
