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

	inputField := tview.NewInputField().
		SetText(defaultValue).
		SetFieldWidth(35).
		SetFieldBackgroundColor(ColorBgSelect).
		SetFieldTextColor(tcell.NewRGBColor(0, 0, 0)).  // 黑色文字，确保在明亮背景上清晰可见
		SetPlaceholder("请输入...").
		SetPlaceholderTextColor(tcell.NewRGBColor(60, 60, 60)).  // 深灰色占位符
		SetLabelColor(ColorNeonCyan)

	container := tview.NewFlex().SetDirection(tview.FlexRow)

	titleText := tview.NewTextView().
		SetDynamicColors(true).
		SetText(fmt.Sprintf("%s✦%s %s%s%s", alt, resetTag, accent, title, resetTag)).
		SetTextAlign(tview.AlignCenter)
	titleText.SetBackgroundColor(ColorBgPanel)
	titleText.SetTextColor(ColorAccent)

	inputRow := tview.NewFlex().
		AddItem(nil, 2, 0, false).
		AddItem(inputField, 0, 1, true).
		AddItem(nil, 2, 0, false)

	hintText := tview.NewTextView().
		SetDynamicColors(true).
		SetText(fmt.Sprintf("%sEnter%s 确认    %sEsc%s 取消", accent, resetTag, alt, resetTag)).
		SetTextAlign(tview.AlignCenter)
	hintText.SetBackgroundColor(ColorBgPanel)
	hintText.SetTextColor(ColorTextDim)

	container.
		AddItem(titleText, 1, 0, false).
		AddItem(nil, 1, 0, false).
		AddItem(inputRow, 1, 0, true).
		AddItem(nil, 1, 0, false).
		AddItem(hintText, 1, 0, false)

	container.SetBorder(true).
		SetBorderColor(ColorBorderActive).
		SetTitle(t.formatPanelTitle("✦", "输入")).
		SetBackgroundColor(ColorBgPanel).
		SetBorderPadding(1, 1, 2, 2)

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
			AddItem(container, 9, 0, true).
			AddItem(nil, 0, 1, false), 50, 0, true).
		AddItem(nil, 0, 1, false)

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
			callback(buttonIndex == 0)
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

	container.SetBorder(true).
		SetTitle(fmt.Sprintf(" %s◈%s %s%s%s ", alt, resetTag, accent, title, resetTag)).
		SetTitleAlign(tview.AlignCenter).
		SetTitleColor(ColorAccent).
		SetBorderColor(ColorBorderActive).
		SetBackgroundColor(ColorBgPanel).
		SetBorderPadding(0, 0, 1, 1)

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
			AddItem(container, 0, 3, true).
			AddItem(nil, 0, 1, false), 0, 2, true).
		AddItem(nil, 0, 1, false)

	t.showModalPage("info", modal)
	t.app.SetFocus(textView)
}

// showLoadingDialog 显示加载动画对话框
func (t *TUIApp) showLoadingDialog(message string) *Spinner {
	spinner := NewSpinner(t.app)
	spinner.SetText(ColorTag(ColorAccent)+message+resetTag, "")

	container := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(nil, 0, 1, false).
		AddItem(spinner.GetView(), 1, 0, false).
		AddItem(nil, 0, 1, false)

	container.SetBorder(true).
		SetBorderColor(ColorBorderActive).
		SetTitle(t.formatPanelTitle("⏳", "处理中")).
		SetBackgroundColor(ColorBgPanel).
		SetBorderPadding(1, 1, 2, 2)

	modal := tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, 0, 1, false).
			AddItem(container, 5, 0, false).
			AddItem(nil, 0, 1, false), 40, 0, false).
		AddItem(nil, 0, 1, false)

	t.showModalPage("loading", modal)
	spinner.Start()

	return spinner
}

// hideLoadingDialog 隐藏加载动画对话框
func (t *TUIApp) hideLoadingDialog(spinner *Spinner) {
	if spinner != nil {
		spinner.Stop()
	}
	t.hideModalPage("loading")
	t.app.SetFocus(t.menuList)
}
