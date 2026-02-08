package main

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// ============================================================================
// Cyberpunk 配色方案
// ============================================================================

// 背景色系
var (
	ColorBgDeep   = tcell.NewRGBColor(13, 2, 33)   // #0D0221 深紫黑
	ColorBgMain   = tcell.NewRGBColor(20, 10, 45)  // #140A2D 主背景
	ColorBgPanel  = tcell.NewRGBColor(30, 15, 60)  // #1E0F3C 面板背景
	ColorBgSelect = tcell.NewRGBColor(0, 180, 200) // #00B4C8 明亮的青色选中背景（高对比度，黑色文字清晰可见）
)

// 霓虹色系
var (
	ColorNeonPink   = tcell.NewRGBColor(255, 0, 255) // #FF00FF 霓虹粉
	ColorNeonCyan   = tcell.NewRGBColor(0, 255, 255) // #00FFFF 电光蓝
	ColorNeonGreen  = tcell.NewRGBColor(57, 255, 20) // #39FF14 荧光绿
	ColorNeonYellow = tcell.NewRGBColor(255, 233, 0) // #FFE900 激光黄
	ColorNeonOrange = tcell.NewRGBColor(255, 95, 31) // #FF5F1F 霓虹橙
	ColorNeonPurple = tcell.NewRGBColor(191, 0, 255) // #BF00FF 霓虹紫
)

// 文字色系
var (
	ColorTextBright = tcell.NewRGBColor(255, 255, 255) // #FFFFFF 高亮白
	ColorTextNormal = tcell.NewRGBColor(200, 200, 220) // #C8C8DC 普通文字
	ColorTextDim    = tcell.NewRGBColor(120, 100, 150) // #786496 暗淡文字
)

// 语义化颜色别名
var (
	ColorAccent    = ColorNeonCyan   // 主强调色
	ColorAccentAlt = ColorNeonPink   // 次强调色
	ColorSuccess   = ColorNeonGreen  // 成功
	ColorWarning   = ColorNeonYellow // 警告
	ColorError     = ColorNeonOrange // 错误
	ColorSpecial   = ColorNeonPurple // 特殊

	ColorBorder       = ColorNeonPurple // 普通边框
	ColorBorderActive = ColorNeonCyan   // 激活边框

	ColorBgSecondary   = ColorBgPanel  // 次要背景
	ColorBgHighlight   = ColorBgSelect // 高亮背景
	ColorTextPrimary   = ColorTextBright
	ColorTextSecondary = ColorTextNormal
	ColorTextMuted     = ColorTextDim
)

// ============================================================================
// 主题系统
// ============================================================================

// Theme 主题配色
type Theme struct {
	Name string

	BgDeep   tcell.Color
	BgMain   tcell.Color
	BgPanel  tcell.Color
	BgSelect tcell.Color

	NeonPink   tcell.Color
	NeonCyan   tcell.Color
	NeonGreen  tcell.Color
	NeonYellow tcell.Color
	NeonOrange tcell.Color
	NeonPurple tcell.Color

	TextBright tcell.Color
	TextNormal tcell.Color
	TextDim    tcell.Color
}

var themes = map[string]Theme{
	"cyberpunk": {
		Name:       "Cyberpunk",
		BgDeep:     tcell.NewRGBColor(13, 2, 33),
		BgMain:     tcell.NewRGBColor(20, 10, 45),
		BgPanel:    tcell.NewRGBColor(30, 15, 60),
		BgSelect:   tcell.NewRGBColor(0, 180, 200),  // #00B4C8 明亮的青色选中背景（高对比度，黑色文字清晰可见）
		NeonPink:   tcell.NewRGBColor(255, 0, 255),
		NeonCyan:   tcell.NewRGBColor(0, 255, 255),
		NeonGreen:  tcell.NewRGBColor(57, 255, 20),
		NeonYellow: tcell.NewRGBColor(255, 233, 0),
		NeonOrange: tcell.NewRGBColor(255, 95, 31),
		NeonPurple: tcell.NewRGBColor(191, 0, 255),
		TextBright: tcell.NewRGBColor(255, 255, 255),
		TextNormal: tcell.NewRGBColor(200, 200, 220),
		TextDim:    tcell.NewRGBColor(120, 100, 150),
	},
	"matrix": {
		Name:       "Matrix",
		BgDeep:     tcell.NewRGBColor(6, 18, 10),
		BgMain:     tcell.NewRGBColor(10, 28, 16),
		BgPanel:    tcell.NewRGBColor(14, 40, 22),
		BgSelect:   tcell.NewRGBColor(57, 255, 20),  // #39FF14 荧光绿选中背景（高对比度，黑色文字清晰可见）
		NeonPink:   tcell.NewRGBColor(120, 255, 120),
		NeonCyan:   tcell.NewRGBColor(90, 255, 160),
		NeonGreen:  tcell.NewRGBColor(57, 255, 20),
		NeonYellow: tcell.NewRGBColor(150, 255, 80),
		NeonOrange: tcell.NewRGBColor(120, 230, 80),
		NeonPurple: tcell.NewRGBColor(80, 200, 140),
		TextBright: tcell.NewRGBColor(210, 255, 210),
		TextNormal: tcell.NewRGBColor(150, 230, 170),
		TextDim:    tcell.NewRGBColor(80, 160, 110),
	},
	"ocean": {
		Name:       "Ocean",
		BgDeep:     tcell.NewRGBColor(6, 10, 30),
		BgMain:     tcell.NewRGBColor(10, 18, 45),
		BgPanel:    tcell.NewRGBColor(12, 28, 70),
		BgSelect:   tcell.NewRGBColor(80, 220, 255),  // #50DCFF 明亮的天蓝色选中背景（高对比度，黑色文字清晰可见）
		NeonPink:   tcell.NewRGBColor(255, 120, 200),
		NeonCyan:   tcell.NewRGBColor(80, 220, 255),
		NeonGreen:  tcell.NewRGBColor(80, 255, 200),
		NeonYellow: tcell.NewRGBColor(255, 230, 120),
		NeonOrange: tcell.NewRGBColor(255, 170, 80),
		NeonPurple: tcell.NewRGBColor(170, 120, 255),
		TextBright: tcell.NewRGBColor(235, 245, 255),
		TextNormal: tcell.NewRGBColor(180, 210, 235),
		TextDim:    tcell.NewRGBColor(120, 150, 190),
	},
}

var currentThemeName = "cyberpunk"

// ApplyTheme 应用主题
func ApplyTheme(name string) bool {
	theme, ok := themes[name]
	if !ok {
		return false
	}

	ColorBgDeep = theme.BgDeep
	ColorBgMain = theme.BgMain
	ColorBgPanel = theme.BgPanel
	ColorBgSelect = theme.BgSelect

	ColorNeonPink = theme.NeonPink
	ColorNeonCyan = theme.NeonCyan
	ColorNeonGreen = theme.NeonGreen
	ColorNeonYellow = theme.NeonYellow
	ColorNeonOrange = theme.NeonOrange
	ColorNeonPurple = theme.NeonPurple

	ColorTextBright = theme.TextBright
	ColorTextNormal = theme.TextNormal
	ColorTextDim = theme.TextDim

	applyDerivedColors()
	currentThemeName = name
	return true
}

// GetThemeNames 获取主题名列表
func GetThemeNames() []string {
	names := make([]string, 0, len(themes))
	for name := range themes {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// CurrentThemeName 当前主题名
func CurrentThemeName() string {
	return currentThemeName
}

// ColorTag 生成 tview 颜色标签
func ColorTag(color tcell.Color) string {
	r, g, b := color.RGB()
	return fmt.Sprintf("[#%02X%02X%02X]", r, g, b)
}

func applyDerivedColors() {
	ColorAccent = ColorNeonCyan
	ColorAccentAlt = ColorNeonPink
	ColorSuccess = ColorNeonGreen
	ColorWarning = ColorNeonYellow
	ColorError = ColorNeonOrange
	ColorSpecial = ColorNeonPurple

	ColorBorder = ColorNeonPurple
	ColorBorderActive = ColorNeonCyan

	ColorBgSecondary = ColorBgPanel
	ColorBgHighlight = ColorBgSelect
	ColorTextPrimary = ColorTextBright
	ColorTextSecondary = ColorTextNormal
	ColorTextMuted = ColorTextDim
}

func init() {
	applyDerivedColors()
}

// ============================================================================
// ASCII Art 标题
// ============================================================================

const ASCIILogo = `[#00FFFF]╔══════════════════════════════════════════════════════════════╗
║[#FF00FF]  ████████╗██╗     ███████╗   ██╗   ██╗██████╗ ███╗   ██╗  [#00FFFF]║
║[#FF00FF]  ╚══██╔══╝██║     ██╔════╝   ██║   ██║██╔══██╗████╗  ██║  [#00FFFF]║
║[#FF00FF]     ██║   ██║     ███████╗   ██║   ██║██████╔╝██╔██╗ ██║  [#00FFFF]║
║[#FF00FF]     ██║   ██║     ╚════██║   ╚██╗ ██╔╝██╔═══╝ ██║╚██╗██║  [#00FFFF]║
║[#FF00FF]     ██║   ███████╗███████║    ╚████╔╝ ██║     ██║ ╚████║  [#00FFFF]║
║[#FF00FF]     ╚═╝   ╚══════╝╚══════╝     ╚═══╝  ╚═╝     ╚═╝  ╚═══╝  [#00FFFF]║
╚══════════════════════════════════════════════════════════════╝[-]`

const ASCIILogoCompact = `[#00FFFF]╔════════════════════════════════════════════╗
║[#FF00FF]  ▀█▀ █   █▀   █ █ █▀█ █▄ █  [#00FFFF]║
║[#FF00FF]   █  █▄▄ ▄█   ▀▄▀ █▀▀ █ ▀█  [#00FFFF]║
╚════════════════════════════════════════════╝[-]`

// ============================================================================
// 菜单图标 (霓虹风格)
// ============================================================================

const (
	IconServer     = "◈ "
	IconClient     = "◇ "
	IconConfig     = "⚙ "
	IconWizard     = "★ "
	IconExit       = "✖ "
	IconStart      = "▶ "
	IconStop       = "■ "
	IconSettings   = "⚙ "
	IconCert       = "⬡ "
	IconToken      = "◆ "
	IconUsers      = "⬢ "
	IconKick       = "⊗ "
	IconStats      = "▤ "
	IconNetwork    = "◎ "
	IconRoute      = "➤ "
	IconDNS        = "◉ "
	IconSave       = "▼ "
	IconLoad       = "▲ "
	IconView       = "◐ "
	IconReset      = "↻ "
	IconAdd        = "+ "
	IconRemove     = "- "
	IconBack       = "◀ "
	IconConnect    = "⚡"
	IconDisconnect = "⦸ "
	IconGenerate   = "✦ "
	IconRequest    = "➚ "
	IconStatus     = "▣ "

	// 状态指示符
	StatusRunning      = "●"
	StatusStopped      = "○"
	StatusConnected    = "●"
	StatusDisconnected = "○"
)

// 应用信息
const (
	AppName    = "TLS VPN"
	AppVersion = "v1.0"
	AppTitle   = "⚡ " + AppName + " " + AppVersion
)

// ============================================================================
// Spinner 加载动画
// ============================================================================

// Spinner 加载动画组件
type Spinner struct {
	frames   []string
	current  int
	running  bool
	mu       sync.Mutex
	textView *tview.TextView
	prefix   string
	suffix   string
	stopCh   chan struct{}
	app      *tview.Application
}

// 霓虹风格 Spinner 帧
var SpinnerFrames = []string{
	"[#FF00FF]⠋[-]", "[#FF00FF]⠙[-]", "[#FF00FF]⠹[-]", "[#00FFFF]⠸[-]",
	"[#00FFFF]⠼[-]", "[#00FFFF]⠴[-]", "[#39FF14]⠦[-]", "[#39FF14]⠧[-]",
	"[#39FF14]⠇[-]", "[#FFE900]⠏[-]", "[#FFE900]⠋[-]", "[#FF00FF]⠙[-]",
}

var SpinnerFramesBlock = []string{
	"[#FF00FF]▰▱▱▱▱[-]", "[#FF00FF]▰▰▱▱▱[-]", "[#00FFFF]▰▰▰▱▱[-]",
	"[#00FFFF]▰▰▰▰▱[-]", "[#39FF14]▰▰▰▰▰[-]", "[#39FF14]▱▰▰▰▰[-]",
	"[#FFE900]▱▱▰▰▰[-]", "[#FFE900]▱▱▱▰▰[-]", "[#FF00FF]▱▱▱▱▰[-]",
}

// NewSpinner 创建新的 Spinner
func NewSpinner(app *tview.Application) *Spinner {
	tv := tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignCenter)
	tv.SetBackgroundColor(ColorBgPanel)

	return &Spinner{
		frames:   SpinnerFrames,
		textView: tv,
		app:      app,
		stopCh:   make(chan struct{}),
	}
}

// SetText 设置 Spinner 文本
func (s *Spinner) SetText(prefix, suffix string) *Spinner {
	s.mu.Lock()
	s.prefix = prefix
	s.suffix = suffix
	s.mu.Unlock()
	return s
}

// GetView 获取 TextView
func (s *Spinner) GetView() *tview.TextView {
	return s.textView
}

// Start 启动动画
func (s *Spinner) Start() {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.stopCh = make(chan struct{})
	s.mu.Unlock()

	go func() {
		ticker := time.NewTicker(80 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-s.stopCh:
				return
			case <-ticker.C:
				s.mu.Lock()
				s.current = (s.current + 1) % len(s.frames)
				frame := s.frames[s.current]
				text := s.prefix + " " + frame + " " + s.suffix
				s.mu.Unlock()

				s.app.QueueUpdateDraw(func() {
					s.textView.SetText(text)
				})
			}
		}
	}()
}

// Stop 停止动画
func (s *Spinner) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		close(s.stopCh)
		s.running = false
	}
}

// SetFrames 设置动画帧
func (s *Spinner) SetFrames(frames []string) *Spinner {
	s.mu.Lock()
	s.frames = frames
	s.mu.Unlock()
	return s
}
