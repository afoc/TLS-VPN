package main

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// TUIApp TUI 应用程序
type TUIApp struct {
	app              *tview.Application
	pages            *tview.Pages
	menuList         *tview.List
	logView          *tview.TextView
	statusBar        *tview.TextView
	logoView         *tview.TextView
	helpBar          *tview.TextView
	mainFlex         *tview.Flex
	leftPanel        *tview.Flex
	layout           *tview.Flex
	logBuffer        *LogBuffer
	menuStack        []string
	stopChan         chan struct{}
	lastLogSeq       uint64         // 最后获取的日志序号
	client           *ControlClient // IPC 客户端
	lastWidth        int
	lastHeight       int
	logFilter        string
	logFollow        bool
	lastRenderedLog  string
	trafficTxSamples []int
	trafficRxSamples []int
	lastTotalSent    uint64
	lastTotalRecv    uint64
	lastStatAt       time.Time
	borderPulseOn    bool
	borderPulseStop  chan struct{}
	modalOpenCount   int
	modalMu          sync.Mutex
}

// LogBuffer 环形日志缓冲区
type LogBuffer struct {
	lines    []string
	maxLines int
	mu       sync.Mutex
}

// NewLogBuffer 创建日志缓冲区
func NewLogBuffer(maxLines int) *LogBuffer {
	return &LogBuffer{
		lines:    make([]string, 0, maxLines),
		maxLines: maxLines,
	}
}

// Write 实现 io.Writer 接口
func (lb *LogBuffer) Write(p []byte) (n int, err error) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	for _, line := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		if line != "" {
			lb.addLineNoLock(line)
		}
	}
	return len(p), nil
}

// AddLine 添加日志行（自动添加时间戳）
func (lb *LogBuffer) AddLine(line string) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	lb.addLineNoLock(line)
}

// AddLineRaw 添加原始日志行（不添加时间戳，用于已格式化的日志）
func (lb *LogBuffer) AddLineRaw(line string) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	lb.lines = append(lb.lines, line)
	if len(lb.lines) > lb.maxLines {
		lb.lines = lb.lines[1:]
	}
}

func (lb *LogBuffer) addLineNoLock(line string) {
	timestamp := time.Now().Format("15:04:05")
	level := detectLogLevel(line)
	lb.lines = append(lb.lines, formatLogLine(level, line, timestamp))
	if len(lb.lines) > lb.maxLines {
		lb.lines = lb.lines[1:]
	}
}

// GetContent 获取所有日志
func (lb *LogBuffer) GetContent() string {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	return strings.Join(lb.lines, "\n")
}

// GetContentFiltered 获取过滤后的日志内容
func (lb *LogBuffer) GetContentFiltered(filter string) string {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	if strings.TrimSpace(filter) == "" {
		return strings.Join(lb.lines, "\n")
	}
	needle := strings.ToLower(filter)
	filtered := make([]string, 0, len(lb.lines))
	for _, line := range lb.lines {
		plain := strings.ToLower(stripColorTags(line))
		if strings.Contains(plain, needle) {
			filtered = append(filtered, line)
		}
	}
	return strings.Join(filtered, "\n")
}

// Clear 清空日志
func (lb *LogBuffer) Clear() {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	lb.lines = lb.lines[:0]
}

// NewTUIApp 创建 TUI 应用
func NewTUIApp(client *ControlClient) *TUIApp {
	t := &TUIApp{
		app:             tview.NewApplication(),
		pages:           tview.NewPages(),
		logBuffer:       NewLogBuffer(500),
		menuStack:       []string{"main"},
		stopChan:        make(chan struct{}),
		client:          client,
		logFollow:       true,
		borderPulseStop: make(chan struct{}),
	}
	t.setupUI()
	return t
}

// setupUI 设置 UI 布局
func (t *TUIApp) setupUI() {
	// ASCII Art 标题
	t.logoView = tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignCenter)
	t.setLogoText()
	t.logoView.SetBackgroundColor(ColorBgDeep)

	// 日志视图 - 双线边框
	t.logView = tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true)
	t.logView.SetBorder(true).
		SetTitle(t.formatPanelTitle("◈", "系统日志")).
		SetTitleAlign(tview.AlignLeft).
		SetBorderColor(ColorBorder).
		SetBackgroundColor(ColorBgMain).
		SetTitleColor(ColorAccent)
	t.logView.SetBorderPadding(0, 0, 1, 1)

	// 菜单列表 - 双线边框
	t.menuList = tview.NewList().
		SetHighlightFullLine(true).
		SetSelectedBackgroundColor(ColorBgSelect).
		SetSelectedTextColor(tcell.NewRGBColor(0, 0, 0)).  // 黑色文字，确保在明亮背景上清晰可见
		SetMainTextColor(ColorTextNormal).
		SetSecondaryTextColor(ColorTextDim).
		SetShortcutColor(ColorNeonPink)
	t.menuList.SetBorder(true).
		SetBorderColor(ColorBorder).
		SetBackgroundColor(ColorBgMain).
		SetTitleColor(ColorAccent)
	t.menuList.SetBorderPadding(0, 0, 1, 1)

	// 状态栏 - 霓虹风格
	t.statusBar = tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignCenter).
		SetWrap(false)
	t.statusBar.SetBackgroundColor(ColorBgPanel)
	t.statusBar.SetTextColor(ColorTextNormal)

	// 帮助栏 - 霓虹快捷键
	t.helpBar = tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignCenter)
	t.helpBar.SetText(t.buildHelpText())
	t.helpBar.SetBackgroundColor(ColorBgDeep)
	t.helpBar.SetTextColor(ColorTextDim)

	// 左侧面板（菜单）
	t.leftPanel = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(t.menuList, 0, 1, true)

	// 主内容区
	t.mainFlex = tview.NewFlex().
		AddItem(t.leftPanel, 40, 0, true).
		AddItem(t.logView, 0, 1, false)

	// 整体布局
	t.layout = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(t.logoView, 4, 0, false).
		AddItem(t.mainFlex, 0, 1, true).
		AddItem(t.statusBar, 1, 0, false).
		AddItem(t.helpBar, 1, 0, false)

	t.pages.AddPage("main", t.layout, true, true)

	// 设置全局背景色
	t.app.SetBeforeDrawFunc(func(screen tcell.Screen) bool {
		width, height := screen.Size()
		if width != t.lastWidth || height != t.lastHeight {
			t.lastWidth = width
			t.lastHeight = height
			t.adjustLayout(width, height)
		}
		screen.Clear()
		return false
	})

	// 全局按键
	t.app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		frontPage, _ := t.pages.GetFrontPage()
		if frontPage == "input" || frontPage == "confirm" || frontPage == "info" || frontPage == "exitDialog" || frontPage == "loading" {
			return event
		}

		switch event.Key() {
		case tcell.KeyF2:
			t.logBuffer.Clear()
			t.logView.Clear()
			t.logView.SetText("")
			t.addLog("日志已清空")
			t.app.ForceDraw()
			return nil
		case tcell.KeyF3:
			t.toggleLogFollow()
			return nil
		case tcell.KeyF6:
			t.cycleTheme()
			return nil
		case tcell.KeyF1:
			t.showHelpDialog()
			return nil
		case tcell.KeyEsc:
			if len(t.menuStack) > 1 {
				t.menuStack = t.menuStack[:len(t.menuStack)-1]
				t.showMenu(t.menuStack[len(t.menuStack)-1])
				return nil
			}
		case tcell.KeyTab:
			if t.menuList.HasFocus() {
				t.app.SetFocus(t.logView)
			} else {
				t.app.SetFocus(t.menuList)
			}
			t.updateFocusStyles()
			return nil
		}
		switch event.Rune() {
		case '/':
			t.showLogFilterDialog()
			return nil
		case '?':
			t.showHelpDialog()
			return nil
		}
		return event
	})

	t.app.SetRoot(t.pages, true)
	t.updateStatusBar()
	t.updateFocusStyles()
}

const colorResetTag = "[-]"

func tag(color tcell.Color) string {
	return ColorTag(color)
}

func (t *TUIApp) formatPanelTitle(icon, title string) string {
	return fmt.Sprintf(" %s%s%s %s%s%s ", tag(ColorAccent), icon, colorResetTag, tag(ColorAccentAlt), title, colorResetTag)
}

func (t *TUIApp) formatMenuTitle(title string) string {
	return fmt.Sprintf(" %s%s%s ", tag(ColorAccent), title, colorResetTag)
}

func (t *TUIApp) formatMenuLabel(label string, width int) string {
	padding := ""
	if width > 0 {
		pad := width - stringWidth(label)
		if pad > 0 {
			padding = strings.Repeat(" ", pad)
		}
	}
	return label + padding
}

func (t *TUIApp) formatMenuDesc(desc string, hasChild bool) string {
	if desc == "" {
		return ""
	}
	if hasChild {
		return desc + " >"
	}
	return desc
}

func splitIconLabel(label string) (string, string) {
	parts := strings.SplitN(label, " ", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return label, ""
}

func stringWidth(s string) int {
	return len([]rune(s))
}

func (t *TUIApp) buildHelpTextForWidth(width int) string {
	if width <= 0 {
		width = 120
	}
	accent := tag(ColorAccent)
	alt := tag(ColorAccentAlt)
	ok := tag(ColorSuccess)
	warn := tag(ColorWarning)
	muted := tag(ColorTextMuted)

	if width < 90 {
		return fmt.Sprintf("%sTab%s 切换  %sF2%s 清屏  %s/%s 过滤  %sF6%s 主题  %sF1%s 帮助",
			alt, colorResetTag, accent, colorResetTag, ok, colorResetTag, warn, colorResetTag, muted, colorResetTag)
	}
	return fmt.Sprintf("%sTab%s 切换  %sF2%s 清屏  %s/%s 过滤  %sF3%s 跟随  %sF6%s 主题  %sF1%s 帮助  %sEsc%s 返回  %sq%s 退出",
		alt, colorResetTag, accent, colorResetTag, ok, colorResetTag, tag(ColorSpecial), colorResetTag,
		warn, colorResetTag, muted, colorResetTag, tag(ColorTextSecondary), colorResetTag, warn, colorResetTag)
}

func (t *TUIApp) buildHelpText() string {
	return t.buildHelpTextForWidth(t.lastWidth)
}

func (t *TUIApp) setLogoText() {
	width := t.lastWidth
	height := t.lastHeight
	if width >= 120 && height >= 28 {
		t.logoView.SetText(ASCIILogo)
	} else if width >= 70 {
		t.logoView.SetText(ASCIILogoCompact)
	} else {
		title := fmt.Sprintf("%s%s%s %s%s%s", tag(ColorAccentAlt), AppName, colorResetTag, tag(ColorTextSecondary), AppVersion, colorResetTag)
		t.logoView.SetText(title)
	}
}

func (t *TUIApp) adjustLayout(width, height int) {
	menuWidth := 40
	switch {
	case width < 85:
		menuWidth = 26
	case width < 110:
		menuWidth = 32
	}
	t.mainFlex.ResizeItem(t.leftPanel, menuWidth, 0)

	if height < 20 || width < 70 {
		t.layout.ResizeItem(t.logoView, 0, 0)
	} else if width >= 120 && height >= 28 {
		t.logoView.SetText(ASCIILogo)
		t.layout.ResizeItem(t.logoView, 7, 0)
	} else {
		t.logoView.SetText(ASCIILogoCompact)
		t.layout.ResizeItem(t.logoView, 4, 0)
	}

	if height < 24 {
		t.layout.ResizeItem(t.helpBar, 0, 0)
	} else {
		t.layout.ResizeItem(t.helpBar, 1, 0)
	}
	t.layout.ResizeItem(t.statusBar, 1, 0)
	t.helpBar.SetText(t.buildHelpTextForWidth(width))
}

func (t *TUIApp) applyThemeToViews() {
	t.logoView.SetBackgroundColor(ColorBgDeep)
	t.setLogoText()
	t.logView.SetBackgroundColor(ColorBgMain)
	t.logView.SetBorderColor(ColorBorder)
	t.logView.SetTitleColor(ColorAccent)
	t.logView.SetTitle(t.formatPanelTitle("◈", "系统日志"))
	t.menuList.SetMainTextColor(ColorTextNormal)
	t.menuList.SetSecondaryTextColor(ColorTextDim)
	t.menuList.SetSelectedBackgroundColor(ColorBgSelect)
	t.menuList.SetSelectedTextColor(tcell.NewRGBColor(0, 0, 0))  // 黑色文字，确保在明亮背景上清晰可见
	t.menuList.SetShortcutColor(ColorAccentAlt)
	t.menuList.SetBorderColor(ColorBorder)
	t.menuList.SetTitleColor(ColorAccent)
	t.statusBar.SetBackgroundColor(ColorBgPanel)
	t.statusBar.SetTextColor(ColorTextNormal)
	t.helpBar.SetBackgroundColor(ColorBgDeep)
	t.helpBar.SetTextColor(ColorTextDim)
	t.helpBar.SetText(t.buildHelpText())
	t.updateFocusStyles()
	t.updateStatusBar()
}

func (t *TUIApp) cycleTheme() {
	names := GetThemeNames()
	current := CurrentThemeName()
	next := names[0]
	for i, name := range names {
		if name == current {
			next = names[(i+1)%len(names)]
			break
		}
	}
	if ApplyTheme(next) {
		t.applyThemeToViews()
		t.showMenu(t.menuStack[len(t.menuStack)-1])
		t.addLog("主题切换为: %s", next)
	}
}

func (t *TUIApp) toggleLogFollow() {
	t.logFollow = !t.logFollow
	state := "关闭"
	if t.logFollow {
		state = "开启"
	}
	t.addLog("日志自动跟随: %s", state)
}

func (t *TUIApp) showLogFilterDialog() {
	t.showInputDialogWithID("filter", "日志过滤（留空清除）", t.logFilter, func(value string) {
		t.setLogFilter(strings.TrimSpace(value))
	})
}

func (t *TUIApp) setLogFilter(filter string) {
	t.logFilter = filter
	t.updateLogView()
	t.updateStatusBar()
}

func (t *TUIApp) showHelpDialog() {
	content := fmt.Sprintf("%sF1%s 帮助  %sF2%s 清屏  %sF3%s 跟随日志  %sF6%s 主题切换\n%sTab%s 焦点切换  %s/%s 日志过滤  %sEsc%s 返回  %sq%s 退出",
		tag(ColorAccent), colorResetTag, tag(ColorWarning), colorResetTag, tag(ColorSpecial), colorResetTag, tag(ColorAccentAlt), colorResetTag,
		tag(ColorAccent), colorResetTag, tag(ColorSuccess), colorResetTag, tag(ColorTextSecondary), colorResetTag, tag(ColorWarning), colorResetTag)
	t.showInfoDialog("快捷键帮助", content)
}

func (t *TUIApp) updateLogView() {
	content := t.logBuffer.GetContentFiltered(t.logFilter)
	if content == t.lastRenderedLog {
		return
	}
	t.lastRenderedLog = content
	t.logView.SetText(content)
	if t.logFollow {
		t.logView.ScrollToEnd()
	}
}

func (t *TUIApp) markModalOpen() {
	t.modalMu.Lock()
	t.modalOpenCount++
	t.modalMu.Unlock()
}

func (t *TUIApp) markModalClosed() {
	t.modalMu.Lock()
	if t.modalOpenCount > 0 {
		t.modalOpenCount--
	}
	t.modalMu.Unlock()
}

func (t *TUIApp) isModalOpen() bool {
	t.modalMu.Lock()
	defer t.modalMu.Unlock()
	return t.modalOpenCount > 0
}

func (t *TUIApp) updateFocusStyles() {
	if t.menuList.HasFocus() {
		t.menuList.SetBorderColor(ColorBorderActive)
		t.logView.SetBorderColor(ColorBorder)
	} else {
		t.menuList.SetBorderColor(ColorBorder)
		t.logView.SetBorderColor(ColorBorderActive)
	}
}

func (t *TUIApp) startBorderPulse() {
	go func() {
		ticker := time.NewTicker(600 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-t.stopChan:
				return
			case <-ticker.C:
				t.borderPulseOn = !t.borderPulseOn
				t.app.QueueUpdateDraw(func() {
					t.updateFocusStyles()
				})
			}
		}
	}()
}

func (t *TUIApp) showSplashScreen() {
	spinner := NewSpinner(t.app).SetFrames(SpinnerFramesBlock)
	spinner.SetText(tag(ColorAccent)+AppTitle+colorResetTag, "")

	panel := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(nil, 0, 1, false).
		AddItem(spinner.GetView(), 1, 0, false).
		AddItem(nil, 0, 1, false)
	panel.SetBorder(true).
		SetBorderColor(ColorBorderActive).
		SetBackgroundColor(ColorBgPanel).
		SetBorderPadding(1, 1, 2, 2)

	modal := tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, 0, 1, false).
			AddItem(panel, 5, 0, false).
			AddItem(nil, 0, 1, false), 50, 0, false).
		AddItem(nil, 0, 1, false)

	t.pages.AddPage("splash", modal, true, true)
	spinner.Start()

	go func() {
		time.Sleep(900 * time.Millisecond)
		t.app.QueueUpdateDraw(func() {
			spinner.Stop()
			t.pages.RemovePage("splash")
		})
	}()
}

func formatLogLine(level, message, timestamp string) string {
	icon := "ℹ"
	color := ColorTextSecondary
	switch level {
	case "error":
		icon = "✖"
		color = ColorError
	case "warn":
		icon = "⚠"
		color = ColorWarning
	case "success":
		icon = "✔"
		color = ColorSuccess
	case "debug":
		icon = "●"
		color = ColorSpecial
	}
	return fmt.Sprintf("%s%s%s %s%s%s %s%s%s",
		tag(ColorTextMuted), timestamp, colorResetTag,
		tag(color), icon, colorResetTag,
		tag(ColorTextSecondary), message, colorResetTag)
}

func detectLogLevel(message string) string {
	lower := strings.ToLower(message)
	switch {
	case strings.Contains(lower, "[red]") || strings.Contains(lower, "失败") || strings.Contains(lower, "error"):
		return "error"
	case strings.Contains(lower, "[yellow]") || strings.Contains(lower, "警告") || strings.Contains(lower, "warn"):
		return "warn"
	case strings.Contains(lower, "[green]") || strings.Contains(lower, "成功") || strings.Contains(lower, "success"):
		return "success"
	default:
		return "info"
	}
}

func stripColorTags(text string) string {
	var b strings.Builder
	b.Grow(len(text))
	for i := 0; i < len(text); i++ {
		if text[i] != '[' {
			b.WriteByte(text[i])
			continue
		}
		end := strings.IndexByte(text[i:], ']')
		if end == -1 {
			b.WriteByte(text[i])
			continue
		}
		tagText := text[i+1 : i+end]
		if isColorTag(tagText) {
			i += end
			continue
		}
		b.WriteByte(text[i])
	}
	return b.String()
}

func isColorTag(tagText string) bool {
	if tagText == "-" {
		return true
	}
	if strings.HasPrefix(tagText, "#") {
		return len(tagText) == 7
	}
	switch tagText {
	case "red", "green", "yellow", "blue", "white", "black", "gray", "cyan", "magenta":
		return true
	default:
		return false
	}
}

func formatRate(bytesPerSec int) string {
	if bytesPerSec <= 0 {
		return "0 B/s"
	}
	return fmt.Sprintf("%s/s", formatBytes(uint64(bytesPerSec)))
}

func renderSparkline(samples []int, width int) string {
	if width <= 0 || len(samples) == 0 {
		return ""
	}
	if len(samples) > width {
		samples = samples[len(samples)-width:]
	}
	maxVal := 0
	for _, v := range samples {
		if v > maxVal {
			maxVal = v
		}
	}
	if maxVal == 0 {
		return strings.Repeat("▁", len(samples))
	}
	blocks := []rune("▁▂▃▄▅▆▇█")
	var b strings.Builder
	for _, v := range samples {
		level := int(float64(v) / float64(maxVal) * float64(len(blocks)-1))
		if level < 0 {
			level = 0
		} else if level >= len(blocks) {
			level = len(blocks) - 1
		}
		b.WriteRune(blocks[level])
	}
	return b.String()
}

func (t *TUIApp) pushSample(samples *[]int, value int, maxLen int) {
	*samples = append(*samples, value)
	if len(*samples) > maxLen {
		*samples = (*samples)[len(*samples)-maxLen:]
	}
}

func (t *TUIApp) updateTrafficSamples(totalSent, totalRecv uint64, now time.Time) (int, int) {
	if t.lastStatAt.IsZero() {
		t.lastStatAt = now
		t.lastTotalSent = totalSent
		t.lastTotalRecv = totalRecv
		return 0, 0
	}
	elapsed := now.Sub(t.lastStatAt).Seconds()
	if elapsed <= 0 {
		return 0, 0
	}
	txRate := int(float64(totalSent-t.lastTotalSent) / elapsed)
	rxRate := int(float64(totalRecv-t.lastTotalRecv) / elapsed)

	t.lastStatAt = now
	t.lastTotalSent = totalSent
	t.lastTotalRecv = totalRecv

	t.pushSample(&t.trafficTxSamples, txRate, 30)
	t.pushSample(&t.trafficRxSamples, rxRate, 30)
	return txRate, rxRate
}

func clientPulseFrame() string {
	frames := []string{"▁", "▂", "▃", "▄", "▅", "▆", "▇", "█", "▇", "▆", "▅", "▄", "▃", "▂"}
	idx := int(time.Now().UnixNano()/200_000_000) % len(frames)
	return frames[idx]
}

// addLog 添加日志
func (t *TUIApp) addLog(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	level := detectLogLevel(msg)
	timestamp := time.Now().Format("15:04:05")
	t.logBuffer.AddLineRaw(formatLogLine(level, msg, timestamp))
	go func() {
		t.app.QueueUpdateDraw(func() {
			t.updateLogView()
		})
	}()
}

// updateStatusBar 更新状态栏
func (t *TUIApp) updateStatusBar() {
	serverIcon := tag(ColorError) + StatusStopped + colorResetTag
	serverStatus := tag(ColorError) + "未运行" + colorResetTag
	clientIcon := tag(ColorError) + StatusDisconnected + colorResetTag
	clientStatus := tag(ColorError) + "未连接" + colorResetTag

	var serverRunning bool
	var clientConnected bool
	var txRate int
	var rxRate int
	if t.client.IsServiceRunning() {
		if status, err := t.client.ServerStatus(); err == nil && status.Running {
			serverRunning = true
			serverIcon = tag(ColorSuccess) + StatusRunning + colorResetTag
			serverStatus = fmt.Sprintf("%s运行中%s %s(%d)%s", tag(ColorSuccess), colorResetTag, tag(ColorAccent), status.ClientCount, colorResetTag)
			txRate, rxRate = t.updateTrafficSamples(status.TotalSent, status.TotalRecv, time.Now())
		}
		if status, err := t.client.ClientStatus(); err == nil && status.Connected {
			clientConnected = true
			clientIcon = tag(ColorSuccess) + StatusConnected + colorResetTag
			if status.AssignedIP != "" {
				clientStatus = fmt.Sprintf("%s已连接%s %s(%s)%s", tag(ColorSuccess), colorResetTag, tag(ColorAccent), status.AssignedIP, colorResetTag)
			} else {
				clientStatus = tag(ColorWarning) + "连接中..." + colorResetTag
			}
		}
	}
	if !serverRunning {
		t.lastStatAt = time.Time{}
	}

	nowText := fmt.Sprintf("%s%s%s", tag(ColorTextMuted), time.Now().Format("15:04:05"), colorResetTag)
	filterText := ""
	if t.logFilter != "" {
		filterText = fmt.Sprintf("%s  %s过滤:%s%s", tag(ColorTextMuted), tag(ColorWarning), t.logFilter, colorResetTag)
	}

	width := t.lastWidth
	if width <= 0 {
		width = 120
	}
	base := fmt.Sprintf(" %s◈%s 服务端: %s %s   %s│%s   %s◇%s 客户端: %s %s ",
		tag(ColorAccentAlt), colorResetTag, serverIcon, serverStatus,
		tag(ColorSpecial), colorResetTag,
		tag(ColorAccent), colorResetTag, clientIcon, clientStatus)

	if width < 95 {
		t.statusBar.SetText(base + " " + nowText)
		return
	}

	if width < 130 {
		rateText := fmt.Sprintf(" %s↑%s %s  %s↓%s %s", tag(ColorSuccess), colorResetTag, formatRate(txRate),
			tag(ColorAccent), colorResetTag, formatRate(rxRate))
		clientRateText := ""
		if clientConnected {
			pulse := clientPulseFrame()
			clientRateText = fmt.Sprintf("  %s↑%s -- %s  %s↓%s -- %s",
				tag(ColorSuccess), colorResetTag, tag(ColorTextMuted)+pulse+colorResetTag,
				tag(ColorAccent), colorResetTag, tag(ColorTextMuted)+pulse+colorResetTag)
		}
		t.statusBar.SetText(base + rateText + clientRateText + filterText + " " + nowText)
		return
	}

	sparkWidth := 12
	txSpark := renderSparkline(t.trafficTxSamples, sparkWidth)
	rxSpark := renderSparkline(t.trafficRxSamples, sparkWidth)
	rateText := fmt.Sprintf(" %s↑%s %s %s  %s↓%s %s %s",
		tag(ColorSuccess), colorResetTag, formatRate(txRate), tag(ColorTextMuted)+txSpark+colorResetTag,
		tag(ColorAccent), colorResetTag, formatRate(rxRate), tag(ColorTextMuted)+rxSpark+colorResetTag)

	clientRateText := ""
	if clientConnected {
		pulse := clientPulseFrame()
		clientRateText = fmt.Sprintf("  %s↑%s -- %s  %s↓%s -- %s",
			tag(ColorSuccess), colorResetTag, tag(ColorTextMuted)+pulse+colorResetTag,
			tag(ColorAccent), colorResetTag, tag(ColorTextMuted)+pulse+colorResetTag)
	}
	t.statusBar.SetText(base + rateText + clientRateText + filterText + " " + nowText)
}

// startUpdater 启动状态更新器
func (t *TUIApp) startUpdater() {
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-t.stopChan:
				return
			case <-ticker.C:
				// 从后台服务获取新日志
				t.fetchServiceLogs()

				t.app.QueueUpdateDraw(func() {
					if t.isModalOpen() {
						return
					}
					t.updateLogView()
					t.updateStatusBar()
				})
			}
		}
	}()
}

// fetchServiceLogs 从后台服务获取日志
func (t *TUIApp) fetchServiceLogs() {
	if !t.client.IsServiceRunning() {
		return
	}

	resp, err := t.client.LogFetch(t.lastLogSeq, 50)
	if err != nil {
		return
	}

	// 添加新日志到本地缓冲区
	for _, entry := range resp.Logs {
		// 格式化时间
		logTime := time.UnixMilli(entry.Time).Format("15:04:05")

		t.logBuffer.AddLineRaw(formatLogLine(entry.Level, entry.Message, logTime))
	}

	// 更新最后序号
	if resp.LastSeq > t.lastLogSeq {
		t.lastLogSeq = resp.LastSeq
	}
}

// showMenu 显示菜单
func (t *TUIApp) showMenu(menuName string) {
	t.menuList.Clear()

	menus := GetMenus()
	menuDef, ok := menus[menuName]
	if !ok {
		t.addLog("[#FF5F1F]✖ 未知菜单: %s[-]", menuName)
		return
	}

	t.menuList.SetTitle(t.formatMenuTitle(menuDef.Title))

	maxWidth := 0
	for _, item := range menuDef.Items {
		if w := stringWidth(item.Label); w > maxWidth {
			maxWidth = w
		}
	}

	for _, item := range menuDef.Items {
		itemCopy := item // 避免闭包问题
		label := t.formatMenuLabel(itemCopy.Label, maxWidth)
		desc := t.formatMenuDesc(itemCopy.Desc, itemCopy.NavTo != "")
		t.menuList.AddItem(label, desc, itemCopy.Shortcut, func() {
			if itemCopy.NavTo != "" {
				// 导航到子菜单
				t.navigateTo(itemCopy.NavTo)
			} else if itemCopy.Handler != nil {
				// 执行处理函数
				itemCopy.Handler(t)
			}
		})
	}

	// 自动添加返回上级
	if menuDef.Parent != "" {
		label := t.formatMenuLabel("◀ 返回上级", maxWidth)
		t.menuList.AddItem(label, "", 'b', func() {
			if len(t.menuStack) > 1 {
				t.menuStack = t.menuStack[:len(t.menuStack)-1]
				t.showMenu(t.menuStack[len(t.menuStack)-1])
			}
		})
	}

	t.menuList.SetCurrentItem(0)
	t.app.SetFocus(t.menuList)
	t.app.ForceDraw()
}

// navigateTo 导航到子菜单
func (t *TUIApp) navigateTo(menuName string) {
	t.menuStack = append(t.menuStack, menuName)
	t.showMenu(menuName)
}

// Run 运行应用
func (t *TUIApp) Run() error {
	t.showSplashScreen()
	t.showMenu("main")
	t.logBuffer.AddLineRaw(formatLogLine("info", "TLS VPN 管理系统已启动", time.Now().Format("15:04:05")))
	t.updateLogView()

	go func() {
		time.Sleep(100 * time.Millisecond)
		t.startUpdater()
	}()

	return t.app.Run()
}

// Stop 停止应用
func (t *TUIApp) Stop() {
	select {
	case <-t.stopChan:
		return // 已经关闭
	default:
		close(t.stopChan)
	}
	t.app.Stop()
}

// RequestExit 请求退出
func (t *TUIApp) RequestExit() {
	// 检查是否有活跃的 VPN 服务
	hasActiveVPN := false
	if t.client.IsServiceRunning() {
		if status, err := t.client.ServerStatus(); err == nil && status.Running {
			hasActiveVPN = true
		}
		if status, err := t.client.ClientStatus(); err == nil && status.Connected {
			hasActiveVPN = true
		}
	}

	if hasActiveVPN {
		// 有 VPN 运行，显示对话框让用户选择
		t.showExitDialog()
	} else {
		// 没有 VPN 运行，直接停止后台服务并退出
		t.addLog("正在停止后台服务...")
		t.client.Shutdown()
		t.Stop()
	}
}

// showExitDialog 显示退出确认对话框（仅当有 VPN 运行时）
func (t *TUIApp) showExitDialog() {
	modal := tview.NewModal().
		SetText(fmt.Sprintf("%s⚡%s VPN 服务正在运行\n\n退出后服务将继续在后台运行", tag(ColorAccent), colorResetTag)).
		AddButtons([]string{"退出界面", "停止服务", "取消"}).
		SetBackgroundColor(ColorBgPanel).
		SetTextColor(ColorTextBright).
		SetButtonBackgroundColor(ColorAccent).
		SetButtonTextColor(ColorBgDeep).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			t.hideModalPage("exitDialog")
			t.app.SetFocus(t.menuList)

			switch buttonIndex {
			case 0: // 退出管理界面（服务继续后台运行）
				t.addLog("退出管理界面，服务继续后台运行")
				t.Stop()
			case 1: // 停止后台服务
				t.addLog("正在停止后台服务...")
				if _, err := t.client.Shutdown(); err != nil {
					t.addLog("停止失败: %v", err)
				} else {
					t.addLog("后台服务已停止")
				}
				t.Stop()
			case 2: // 取消
				t.addLog("取消退出")
			}
		})

	modal.SetTitle(t.formatPanelTitle("⚠", "退出确认"))
	modal.SetBorder(true)
	t.showModalPage("exitDialog", modal)
	t.app.SetFocus(modal)
}
