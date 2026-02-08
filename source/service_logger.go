package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// RotatingFileWriter 支持自动轮转的日志文件写入器
type RotatingFileWriter struct {
	filePath    string
	maxSize     int64 // 最大文件大小（字节）
	maxBackups  int   // 最多保留几个备份文件
	currentSize int64
	file        *os.File
	mu          sync.Mutex
}

// NewRotatingFileWriter 创建轮转日志写入器
func NewRotatingFileWriter(filePath string, maxSizeMB int, maxBackups int) (*RotatingFileWriter, error) {
	w := &RotatingFileWriter{
		filePath:   filePath,
		maxSize:    int64(maxSizeMB) * 1024 * 1024,
		maxBackups: maxBackups,
	}

	if err := w.openFile(); err != nil {
		return nil, err
	}

	return w, nil
}

func (w *RotatingFileWriter) openFile() error {
	file, err := os.OpenFile(w.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}

	// 获取当前文件大小
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return err
	}

	w.file = file
	w.currentSize = info.Size()
	return nil
}

// Write 实现 io.Writer 接口
func (w *RotatingFileWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// 检查是否需要轮转
	if w.currentSize+int64(len(p)) > w.maxSize {
		if err := w.rotate(); err != nil {
			// 轮转失败，继续写入当前文件
			fmt.Fprintf(os.Stderr, "日志轮转失败: %v\n", err)
		}
	}

	n, err = w.file.Write(p)
	w.currentSize += int64(n)
	return
}

// rotate 执行日志轮转
func (w *RotatingFileWriter) rotate() error {
	// 关闭当前文件
	if w.file != nil {
		w.file.Close()
	}

	// 删除最旧的备份文件
	oldestBackup := fmt.Sprintf("%s.%d", w.filePath, w.maxBackups)
	os.Remove(oldestBackup)

	// 重命名备份文件（从后往前）
	for i := w.maxBackups - 1; i >= 1; i-- {
		oldName := fmt.Sprintf("%s.%d", w.filePath, i)
		newName := fmt.Sprintf("%s.%d", w.filePath, i+1)
		os.Rename(oldName, newName)
	}

	// 将当前日志文件重命名为 .1
	if err := os.Rename(w.filePath, w.filePath+".1"); err != nil {
		// 如果重命名失败，尝试直接打开新文件
	}

	// 创建新文件
	w.currentSize = 0
	return w.openFile()
}

// Close 关闭文件
func (w *RotatingFileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		return w.file.Close()
	}
	return nil
}

// GetCurrentSize 获取当前文件大小
func (w *RotatingFileWriter) GetCurrentSize() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.currentSize
}

// ServiceLogBuffer 服务端日志缓冲区（带序号的环形缓冲区）
type ServiceLogBuffer struct {
	entries []LogEntry
	maxSize int
	nextSeq uint64
	mu      sync.RWMutex
	fileOut io.Writer // 文件输出
}

// NewServiceLogBuffer 创建服务端日志缓冲区
func NewServiceLogBuffer(maxSize int, fileOut io.Writer) *ServiceLogBuffer {
	return &ServiceLogBuffer{
		entries: make([]LogEntry, 0, maxSize),
		maxSize: maxSize,
		nextSeq: 1,
		fileOut: fileOut,
	}
}

// GetLogFilePath 获取日志文件路径
func GetLogFilePath() string {
	return filepath.Join("/var/log", "tls-vpn.log")
}

// Write 实现 io.Writer 接口，用于接收 log 包的输出
func (b *ServiceLogBuffer) Write(p []byte) (n int, err error) {
	msg := strings.TrimSpace(string(p))
	if msg == "" {
		return len(p), nil
	}

	// 解析日志级别
	level := "info"
	if strings.Contains(msg, "错误") || strings.Contains(msg, "失败") || strings.Contains(msg, "Error") {
		level = "error"
	} else if strings.Contains(msg, "警告") || strings.Contains(msg, "Warning") {
		level = "warn"
	}

	// 移除标准 log 包添加的时间前缀（如果有的话）
	// 标准格式: "2006/01/02 15:04:05 message" 或没有前缀
	cleanMsg := msg
	if len(msg) > 20 && msg[4] == '/' && msg[7] == '/' && msg[10] == ' ' {
		// 有日期前缀，跳过
		if idx := strings.Index(msg[11:], " "); idx > 0 {
			cleanMsg = msg[11+idx+1:]
		}
	}

	// 添加到缓冲区
	b.addEntry(level, cleanMsg)

	// 同时写入文件
	if b.fileOut != nil {
		b.fileOut.Write(p)
	}

	return len(p), nil
}

// addEntry 添加日志条目
func (b *ServiceLogBuffer) addEntry(level, message string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	entry := LogEntry{
		Seq:     atomic.AddUint64(&b.nextSeq, 1) - 1,
		Time:    time.Now().UnixMilli(),
		Level:   level,
		Message: message,
	}

	if len(b.entries) >= b.maxSize {
		// 移除最旧的条目
		b.entries = b.entries[1:]
	}
	b.entries = append(b.entries, entry)
}

// AddLog 手动添加日志（供其他模块直接调用）
func (b *ServiceLogBuffer) AddLog(level, format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	b.addEntry(level, message)

	// 同时写入文件
	if b.fileOut != nil {
		timestamp := time.Now().Format("2006/01/02 15:04:05")
		fmt.Fprintf(b.fileOut, "%s [%s] %s\n", timestamp, strings.ToUpper(level), message)
	}
}

// Info 记录信息日志
func (b *ServiceLogBuffer) Info(format string, args ...interface{}) {
	b.AddLog("info", format, args...)
}

// Warn 记录警告日志
func (b *ServiceLogBuffer) Warn(format string, args ...interface{}) {
	b.AddLog("warn", format, args...)
}

// Error 记录错误日志
func (b *ServiceLogBuffer) Error(format string, args ...interface{}) {
	b.AddLog("error", format, args...)
}

// GetLogsSince 获取指定序号之后的日志
func (b *ServiceLogBuffer) GetLogsSince(since uint64, limit int) ([]LogEntry, uint64) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if len(b.entries) == 0 {
		return nil, since
	}

	// 找到第一条序号大于 since 的日志
	startIdx := -1
	for i, entry := range b.entries {
		if entry.Seq > since {
			startIdx = i
			break
		}
	}

	if startIdx == -1 {
		// 没有新日志
		return nil, b.entries[len(b.entries)-1].Seq
	}

	// 获取日志
	result := b.entries[startIdx:]
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}

	// 复制结果，避免外部修改
	logs := make([]LogEntry, len(result))
	copy(logs, result)

	lastSeq := logs[len(logs)-1].Seq
	return logs, lastSeq
}

// GetLastSeq 获取最后一条日志的序号
func (b *ServiceLogBuffer) GetLastSeq() uint64 {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if len(b.entries) == 0 {
		return 0
	}
	return b.entries[len(b.entries)-1].Seq
}

// Clear 清空日志
func (b *ServiceLogBuffer) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries = b.entries[:0]
}

// 全局日志缓冲区实例
var serviceLogger *ServiceLogBuffer

// InitServiceLogger 初始化服务端日志系统
func InitServiceLogger(fileOut io.Writer) *ServiceLogBuffer {
	serviceLogger = NewServiceLogBuffer(1000, fileOut)
	return serviceLogger
}

// GetServiceLogger 获取全局日志缓冲区
func GetServiceLogger() *ServiceLogBuffer {
	return serviceLogger
}

// SLog 快捷函数：记录服务日志
func SLog(format string, args ...interface{}) {
	if serviceLogger != nil {
		serviceLogger.Info(format, args...)
	}
}

// SLogWarn 快捷函数：记录警告日志
func SLogWarn(format string, args ...interface{}) {
	if serviceLogger != nil {
		serviceLogger.Warn(format, args...)
	}
}

// SLogError 快捷函数：记录错误日志
func SLogError(format string, args ...interface{}) {
	if serviceLogger != nil {
		serviceLogger.Error(format, args...)
	}
}
