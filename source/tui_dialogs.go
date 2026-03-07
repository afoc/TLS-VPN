package main

import (
	"fmt"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

const resetTag = "[-]"

func (t *TUIApp) showModalPage(pageID string, modal tview.Primitive) {
	t.pages.AddPage(pageID, modal, true, true)
	t.markModalOpen()
}

func (t *TUIApp) hideModalPage(pageID string) {
	t.pages.RemovePage(pageID)
	t.markModalClosed()
}

// showInputDialog 显示输入对话框
func (t *TUIApp) showInputDialog(title, defaultValue string, callback func(string)) {
	t.showInputDialogWithID("input", title, defaultValue, callback)
}

// showInputDialogWithID 显示输入对话框（带自定义页面ID，避免冲突）
func (t *TUIApp) showInputDialogWithID(pageID string, title, defaultValue string, callback func(string)) {
	previousFocus := t.menuList
	accent := ColorTag(ColorAccent)
	alt := ColorTag(ColorAccentAlt)
	panelSpacer := func(width int) tview.Primitive {
		return tview.NewBox().SetBackgroundColor(ColorBgPanel)
	}

	inputField := tview.NewInputField().
		SetText(defaultValue).
		SetFieldWidth(35).
		SetFieldBackgroundColor(ColorBgSelect).
		SetFieldTextColor(tcell.NewRGBColor(0, 0, 0)). // 黑色文字，确保在明亮背景上清晰可见
		SetPlaceholder("请输入...").
		SetPlaceholderTextColor(tcell.NewRGBColor(60, 60, 60)). // 深灰色占位符
		SetLabelColor(ColorNeonCyan)

	container := tview.NewFlex().SetDirection(tview.FlexRow)

	titleText := tview.NewTextView().
		SetDynamicColors(true).
		SetText(fmt.Sprintf("%s✦%s %s%s%s", alt, resetTag, accent, title, resetTag)).
		SetTextAlign(tview.AlignCenter)
	titleText.SetBackgroundColor(ColorBgPanel)
	titleText.SetTextColor(ColorAccent)

	inputRow := tview.NewFlex().
		AddItem(panelSpacer(2), 2, 0, false).
		AddItem(inputField, 0, 1, true).
		AddItem(panelSpacer(2), 2, 0, false)
	inputRow.SetBackgroundColor(ColorBgPanel)

	hintText := tview.NewTextView().
		SetDynamicColors(true).
		SetText(fmt.Sprintf("%sEnter%s 确认    %sEsc%s 取消", accent, resetTag, alt, resetTag)).
		SetTextAlign(tview.AlignCenter)
	hintText.SetBackgroundColor(ColorBgPanel)
	hintText.SetTextColor(ColorTextDim)

	container.
		AddItem(titleText, 1, 0, false).
		AddItem(panelSpacer(0), 1, 0, false).
		AddItem(inputRow, 1, 0, true).
		AddItem(panelSpacer(0), 1, 0, false).
		AddItem(hintText, 1, 0, false)

	// 设置容器背景色
	container.SetBackgroundColor(ColorBgPanel)

	// 创建一个包装容器来处理边框和内边距
	wrapper := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(tview.NewBox().SetBackgroundColor(ColorBgPanel), 1, 0, false). // 上边距
		AddItem(tview.NewFlex().
			AddItem(tview.NewBox().SetBackgroundColor(ColorBgPanel), 2, 0, false). // 左边距
			AddItem(container, 0, 1, true).
			AddItem(tview.NewBox().SetBackgroundColor(ColorBgPanel), 2, 0, false), // 右边距
											0, 1, true).
		AddItem(tview.NewBox().SetBackgroundColor(ColorBgPanel), 1, 0, false) // 下边距

	wrapper.SetBorder(true).
		SetBorderColor(ColorBorderActive).
		SetTitle(t.formatPanelTitle("✦", "输入")).
		SetBackgroundColor(ColorBgPanel)

	inputField.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEnter {
			value := inputField.GetText()
			t.hideModalPage(pageID)
			t.app.SetFocus(previousFocus)
			t.app.ForceDraw()
			callback(value)
		}
	})

	inputField.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEscape {
			t.hideModalPage(pageID)
			t.app.SetFocus(previousFocus)
			t.app.ForceDraw()
			return nil
		}
		return event
	})

	modal := tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, 0, 1, false).
			AddItem(wrapper, 9, 0, true).
			AddItem(nil, 0, 1, false), 50, 0, true).
		AddItem(nil, 0, 1, false)

	// 设置 modal 背景色，避免透明显示背景内容
	modal.SetBackgroundColor(ColorBgDeep)

	t.showModalPage(pageID, modal)
	t.app.SetFocus(inputField)
}

// showConfirmDialog 显示确认对话框
func (t *TUIApp) showConfirmDialog(message string, callback func(bool)) {
	t.showConfirmDialogWithID("confirm", message, callback)
}

// showConfirmDialogWithID 显示确认对话框（带自定义页面ID，避免冲突）
func (t *TUIApp) showConfirmDialogWithID(pageID string, message string, callback func(bool)) {
	previousFocus := t.menuList
	warn := ColorTag(ColorWarning)

	modal := tview.NewModal().
		SetText(fmt.Sprintf("%s⚠%s %s", warn, resetTag, message)).
		AddButtons([]string{"  确定  ", "  取消  "}).
		SetBackgroundColor(ColorBgPanel).
		SetTextColor(ColorTextBright).
		SetButtonBackgroundColor(ColorAccent).
		SetButtonTextColor(ColorBgDeep).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			t.hideModalPage(pageID)
			t.app.SetFocus(previousFocus)
			t.app.ForceDraw()
			callback(buttonIndex == 1)
		})

	modal.SetTitle(t.formatPanelTitle("⚠", "确认"))
	modal.SetBorder(true)
	t.showModalPage(pageID, modal)
}

// showYesNoDialog 显示是/否对话框
func (t *TUIApp) showYesNoDialog(message string, callback func(bool)) {
	t.showYesNoDialogWithID("yesno", message, callback)
}

// showYesNoDialogWithID 显示是/否对话框（带自定义页面ID，避免冲突）
func (t *TUIApp) showYesNoDialogWithID(pageID string, message string, callback func(bool)) {
	previousFocus := t.menuList
	warn := ColorTag(ColorWarning)

	modal := tview.NewModal().
		SetText(fmt.Sprintf("%s⚠%s %s", warn, resetTag, message)).
		AddButtons([]string{"  是  ", "  否  "}).
		SetBackgroundColor(ColorBgPanel).
		SetTextColor(ColorTextBright).
		SetButtonBackgroundColor(ColorAccent).
		SetButtonTextColor(ColorBgDeep).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			t.hideModalPage(pageID)
			t.app.SetFocus(previousFocus)
			t.app.ForceDraw()
			callback(buttonIndex == 0)
		})

	modal.SetTitle(t.formatPanelTitle("⚠", "确认"))
	modal.SetBorder(true)
	t.showModalPage(pageID, modal)
}

// showChoiceDialog 显示双选项对话框（用于明确的两个选项）
func (t *TUIApp) showChoiceDialog(pageID string, message string, leftButton string, rightButton string, callback func(bool)) {
	previousFocus := t.menuList
	warn := ColorTag(ColorWarning)

	modal := tview.NewModal().
		SetText(fmt.Sprintf("%s⚠%s %s", warn, resetTag, message)).
		AddButtons([]string{"  " + leftButton + "  ", "  " + rightButton + "  "}).
		SetBackgroundColor(ColorBgPanel).
		SetTextColor(ColorTextBright).
		SetButtonBackgroundColor(ColorAccent).
		SetButtonTextColor(ColorBgDeep).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			t.hideModalPage(pageID)
			t.app.SetFocus(previousFocus)
			t.app.ForceDraw()
			// tview 的按钮索引：右边按钮 = 0，左边按钮 = 1
			// 所以点击右边按钮时返回 true
			callback(buttonIndex == 0)
		})

	modal.SetTitle(t.formatPanelTitle("⚠", "选择"))
	modal.SetBorder(true)
	t.showModalPage(pageID, modal)
}

// showInfoDialog 显示信息对话框
func (t *TUIApp) showInfoDialog(title, content string) {
	previousFocus := t.menuList
	accent := ColorTag(ColorAccent)
	alt := ColorTag(ColorAccentAlt)

	textView := tview.NewTextView().
		SetDynamicColors(true).
		SetText(content).
		SetScrollable(true).
		SetWrap(true)
	textView.SetBackgroundColor(ColorBgPanel)
	textView.SetTextColor(ColorTextNormal)

	hintText := tview.NewTextView().
		SetDynamicColors(true).
		SetText(fmt.Sprintf("%s↑↓%s 滚动    %sEnter/Esc%s 关闭", accent, resetTag, alt, resetTag)).
		SetTextAlign(tview.AlignCenter)
	hintText.SetBackgroundColor(ColorBgPanel)
	hintText.SetTextColor(ColorTextDim)

	container := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(textView, 0, 1, true).
		AddItem(hintText, 1, 0, false)

	// 设置容器背景色
	container.SetBackgroundColor(ColorBgPanel)

	// 创建一个包装容器来处理边框和内边距
	wrapper := tview.NewFlex().
		AddItem(tview.NewBox().SetBackgroundColor(ColorBgPanel), 1, 0, false). // 左边距
		AddItem(container, 0, 1, true).
		AddItem(tview.NewBox().SetBackgroundColor(ColorBgPanel), 1, 0, false) // 右边距

	wrapper.SetBorder(true).
		SetTitle(fmt.Sprintf(" %s◈%s %s%s%s ", alt, resetTag, accent, title, resetTag)).
		SetTitleAlign(tview.AlignCenter).
		SetTitleColor(ColorAccent).
		SetBorderColor(ColorBorderActive).
		SetBackgroundColor(ColorBgPanel)

	textView.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEscape || event.Key() == tcell.KeyEnter {
			t.hideModalPage("info")
			t.app.SetFocus(previousFocus)
			t.app.ForceDraw()
			return nil
		}
		return event
	})

	modal := tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, 0, 1, false).
			AddItem(wrapper, 0, 3, true).
			AddItem(nil, 0, 1, false), 0, 2, true).
		AddItem(nil, 0, 1, false)

	// 设置 modal 背景色，避免透明显示背景内容
	modal.SetBackgroundColor(ColorBgDeep)

	t.showModalPage("info", modal)
	t.app.SetFocus(textView)
}

// showThreeChoiceDialog 显示三选项对话框（使用 List 避免 Modal 的光标问题）
func (t *TUIApp) showThreeChoiceDialog(pageID string, message string, option1, option2, option3 string, callback func(int)) {
	previousFocus := t.menuList
	warn := ColorTag(ColorWarning)
	accent := ColorTag(ColorAccent)
	alt := ColorTag(ColorAccentAlt)

	// 创建消息文本视图
	messageView := tview.NewTextView().
		SetDynamicColors(true).
		SetText(fmt.Sprintf("%s⚠%s %s", warn, resetTag, message)).
		SetTextAlign(tview.AlignCenter).
		SetWrap(true)
	messageView.SetBackgroundColor(ColorBgPanel)
	messageView.SetTextColor(ColorTextBright)

	// 创建选项列表
	optionList := tview.NewList().
		SetHighlightFullLine(true).
		SetSelectedBackgroundColor(ColorBgSelect).
		SetSelectedTextColor(tcell.NewRGBColor(0, 0, 0)).
		SetMainTextColor(ColorTextNormal)
	optionList.SetBackgroundColor(ColorBgPanel)
	optionList.SetBorder(false)

	// 添加选项
	optionList.AddItem(fmt.Sprintf("  %s1%s  %s", accent, resetTag, option1), "", '1', func() {
		t.hideModalPage(pageID)
		t.app.SetFocus(previousFocus)
		t.app.ForceDraw()
		callback(0)
	})
	optionList.AddItem(fmt.Sprintf("  %s2%s  %s", alt, resetTag, option2), "", '2', func() {
		t.hideModalPage(pageID)
		t.app.SetFocus(previousFocus)
		t.app.ForceDraw()
		callback(1)
	})
	optionList.AddItem(fmt.Sprintf("  %s3%s  %s", warn, resetTag, option3), "", '3', func() {
		t.hideModalPage(pageID)
		t.app.SetFocus(previousFocus)
		t.app.ForceDraw()
		callback(2)
	})

	// 提示文本
	hintText := tview.NewTextView().
		SetDynamicColors(true).
		SetText(fmt.Sprintf("%s↑↓%s 选择    %sEnter%s 确认    %sEsc%s 取消", accent, resetTag, alt, resetTag, warn, resetTag)).
		SetTextAlign(tview.AlignCenter)
	hintText.SetBackgroundColor(ColorBgPanel)
	hintText.SetTextColor(ColorTextDim)

	// 容器布局 - 固定高度确保3个选项都可见
	container := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(messageView, 6, 0, false).                                     // 消息区域固定6行
		AddItem(tview.NewBox().SetBackgroundColor(ColorBgPanel), 1, 0, false). // 间隔
		AddItem(optionList, 3, 0, true).                                       // 选项列表固定3行（每个选项1行）
		AddItem(tview.NewBox().SetBackgroundColor(ColorBgPanel), 1, 0, false). // 间隔
		AddItem(hintText, 1, 0, false)                                         // 提示固定1行
	container.SetBackgroundColor(ColorBgPanel)

	// 包装容器（添加边距）
	wrapper := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(tview.NewBox().SetBackgroundColor(ColorBgPanel), 1, 0, false). // 上边距
		AddItem(tview.NewFlex().
			AddItem(tview.NewBox().SetBackgroundColor(ColorBgPanel), 2, 0, false). // 左边距
			AddItem(container, 0, 1, true).
			AddItem(tview.NewBox().SetBackgroundColor(ColorBgPanel), 2, 0, false), // 右边距
											0, 1, true).
		AddItem(tview.NewBox().SetBackgroundColor(ColorBgPanel), 1, 0, false) // 下边距

	wrapper.SetBorder(true).
		SetBorderColor(ColorBorderActive).
		SetTitle(t.formatPanelTitle("⚠", "请选择")).
		SetBackgroundColor(ColorBgPanel)

	// 处理 Esc 键取消
	optionList.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEscape {
			t.hideModalPage(pageID)
			t.app.SetFocus(previousFocus)
			t.app.ForceDraw()
			callback(-1) // -1 表示取消
			return nil
		}
		return event
	})

	// 创建模态框 - 固定总高度为16行（6消息+1间隔+3选项+1间隔+1提示+2边距+2边框）
	modal := tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, 0, 1, false).
			AddItem(wrapper, 16, 0, true). // 固定高度16行
			AddItem(nil, 0, 1, false), 60, 0, true).
		AddItem(nil, 0, 1, false)
	modal.SetBackgroundColor(ColorBgDeep)

	t.showModalPage(pageID, modal)
	t.app.SetFocus(optionList)
}
