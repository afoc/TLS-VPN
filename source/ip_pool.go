package main

import (
	"net"
	"sync"
)

// IPPool IP地址池
type IPPool struct {
	network    *net.IPNet
	allocated  map[string]bool
	freeList   []int          // 新增：空闲IP索引队列
	ipToIndex  map[string]int // 新增：IP到索引的映射
	mutex      sync.RWMutex
	startIndex int // IP范围起始索引
	endIndex   int // IP范围结束索引
}

// NewIPPool 创建IP地址池
func NewIPPool(network *net.IPNet, config *VPNConfig) *IPPool {
	startIndex := config.ClientIPStart
	endIndex := config.ClientIPEnd

	// 初始化空闲列表
	freeList := make([]int, 0, endIndex-startIndex+1)
	for i := startIndex; i <= endIndex; i++ {
		freeList = append(freeList, i)
	}

	return &IPPool{
		network:    network,
		allocated:  make(map[string]bool),
		freeList:   freeList,
		ipToIndex:  make(map[string]int),
		startIndex: startIndex,
		endIndex:   endIndex,
	}
}

// AllocateIP 分配IP地址 - O(1)操作
func (p *IPPool) AllocateIP() net.IP {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if len(p.freeList) == 0 {
		return nil
	}

	// 从队列头取出空闲IP索引
	index := p.freeList[0]
	p.freeList = p.freeList[1:]

	ip := p.network.IP.To4()
	if ip == nil {
		return nil
	}

	allocatedIP := net.IPv4(ip[0], ip[1], ip[2], byte(index))
	ipStr := allocatedIP.String()
	p.allocated[ipStr] = true
	p.ipToIndex[ipStr] = index

	return allocatedIP
}

// ReleaseIP 释放IP地址 - O(1)操作
func (p *IPPool) ReleaseIP(ip net.IP) {
	if ip == nil {
		return
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()

	ipStr := ip.String()
	if p.allocated[ipStr] {
		delete(p.allocated, ipStr)
		if index, ok := p.ipToIndex[ipStr]; ok {
			delete(p.ipToIndex, ipStr)
			// 回收到队列尾部
			p.freeList = append(p.freeList, index)
		}
	}
}

