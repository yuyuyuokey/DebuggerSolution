#include "pch.h"
#include "framework.h"
#include "DebuggerGUI.h"
#include "DebuggerGUIDlg.h"
#include "afxdialogex.h"
#include "DebuggerAPI.h"
#include "CEditRegDlg.h"
#include "resource.h"

HWND g_hMainWnd = NULL;

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

void __stdcall MyDebuggerCallback(int eventType, DWORD dwThreadId)
{
	if (g_hMainWnd) {
		::PostMessage(g_hMainWnd, WM_DEBUG_EVENT, (WPARAM)eventType, (LPARAM)dwThreadId);
	}
}

CDebuggerGUIDlg::CDebuggerGUIDlg(CWnd* pParent) : CDialogEx(IDD_DEBUGGERGUI_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CDebuggerGUIDlg::DoDataExchange(CDataExchange* pDX) { CDialogEx::DoDataExchange(pDX); }

BEGIN_MESSAGE_MAP(CDebuggerGUIDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_MESSAGE(WM_DEBUG_EVENT, &CDebuggerGUIDlg::OnDebugEvent)

	ON_WM_CLOSE()
	ON_WM_SIZE()

	ON_BN_CLICKED(IDC_BTN_START, &CDebuggerGUIDlg::OnBnClickedBtnStart)
	ON_BN_CLICKED(IDC_BTN_STEP_IN, &CDebuggerGUIDlg::OnBnClickedBtnStepIn)
	ON_BN_CLICKED(IDC_BTN_RUN, &CDebuggerGUIDlg::OnBnClickedBtnRun)
	ON_BN_CLICKED(IDC_BTN_STEP_OVER, &CDebuggerGUIDlg::OnBnClickedBtnStepOver)
	ON_BN_CLICKED(IDC_BTN_SET_BP, &CDebuggerGUIDlg::OnBnClickedBtnSetBp)

	ON_NOTIFY(LVN_GETDISPINFO, IDC_LIST_DISASM, &CDebuggerGUIDlg::OnGetdispinfoListDisasm)
	ON_NOTIFY(NM_DBLCLK, IDC_LIST_REGS, &CDebuggerGUIDlg::OnNMDblclkListRegs)

	ON_NOTIFY(LVN_GETDISPINFO, IDC_LIST_MEMORY, &CDebuggerGUIDlg::OnGetdispinfoListMemory)
	ON_NOTIFY(LVN_GETDISPINFO, IDC_LIST_STACK, &CDebuggerGUIDlg::OnGetdispinfoListStack)
	ON_NOTIFY(NM_CUSTOMDRAW, IDC_LIST_DISASM, &CDebuggerGUIDlg::OnCustomDrawListDisasm)

	// 【新增】：鼠标拖拽事件绑定
	ON_WM_LBUTTONDOWN()
	ON_WM_LBUTTONUP()
	ON_WM_MOUSEMOVE()
	ON_WM_SETCURSOR()
END_MESSAGE_MAP()

BOOL CDebuggerGUIDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	SetIcon(m_hIcon, TRUE);
	SetIcon(m_hIcon, FALSE);

	g_hMainWnd = this->GetSafeHwnd();

	// 1. 初始化反汇编列表
	CListCtrl* pListDisasm = (CListCtrl*)GetDlgItem(IDC_LIST_DISASM);
	if (pListDisasm) {
		if ((pListDisasm->GetStyle() & LVS_OWNERDATA) == 0) {
			AfxMessageBox(_T("警告：【反汇编列表】未开启 Owner Data！请去界面属性修改为 True！"));
		}
		// 【核心修复 1】：加回 LVS_EX_HEADERDRAGDROP，允许鼠标按住表头左右拖动交换列！
		pListDisasm->SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_HEADERDRAGDROP);
		pListDisasm->InsertColumn(0, _T("地址"), LVCFMT_LEFT, 100);
		pListDisasm->InsertColumn(1, _T("机器码"), LVCFMT_LEFT, 150);
		pListDisasm->InsertColumn(2, _T("汇编指令"), LVCFMT_LEFT, 200);
		// 【核心修复 2】：把被我不小心删掉的神级第四列加回来！
		pListDisasm->InsertColumn(3, _T("注释"), LVCFMT_LEFT, 300);
	}

	// 2. 初始化寄存器列表
	CListCtrl* pListRegs = (CListCtrl*)GetDlgItem(IDC_LIST_REGS);
	if (pListRegs) {
		// 同样赋予拖拽列的能力
		pListRegs->SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_HEADERDRAGDROP);
		pListRegs->InsertColumn(0, _T("寄存器"), LVCFMT_LEFT, 60);
		pListRegs->InsertColumn(1, _T("数据"), LVCFMT_LEFT, 120);
	}

	// 3. 初始化堆栈列表
	CListCtrl* pListStack = (CListCtrl*)GetDlgItem(IDC_LIST_STACK);
	if (pListStack) {
		if ((pListStack->GetStyle() & LVS_OWNERDATA) == 0) {
			AfxMessageBox(_T("警告：【堆栈列表】未开启 Owner Data！请去界面属性修改为 True！"));
		}
		pListStack->SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_HEADERDRAGDROP);
		pListStack->InsertColumn(0, _T("地址"), LVCFMT_LEFT, 80);
		pListStack->InsertColumn(1, _T("数据"), LVCFMT_LEFT, 80);
		pListStack->InsertColumn(2, _T("注释"), LVCFMT_LEFT, 150);
	}

	// 4. 初始化内存数据列表
	CListCtrl* pListMemory = (CListCtrl*)GetDlgItem(IDC_LIST_MEMORY);
	if (pListMemory) {
		if ((pListMemory->GetStyle() & LVS_OWNERDATA) == 0) {
			AfxMessageBox(_T("警告：【内存列表】未开启 Owner Data！请去界面属性修改为 True！"));
		}
		pListMemory->SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_HEADERDRAGDROP);
		pListMemory->InsertColumn(0, _T("地址"), LVCFMT_LEFT, 80);
		pListMemory->InsertColumn(1, _T("十六进制数据"), LVCFMT_LEFT, 320);
		pListMemory->InsertColumn(2, _T("ASCII"), LVCFMT_LEFT, 150);
	}

	ShowWindow(SW_SHOWMAXIMIZED);
	return TRUE;
}

void CDebuggerGUIDlg::OnPaint()
{
	if (IsIconic()) {
		CPaintDC dc(this);
		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);
		int cxIcon = GetSystemMetrics(SM_CXICON); int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect; GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2; int y = (rect.Height() - cyIcon + 1) / 2;
		dc.DrawIcon(x, y, m_hIcon);
	}
	else { CDialogEx::OnPaint(); }
}

HCURSOR CDebuggerGUIDlg::OnQueryDragIcon() { return static_cast<HCURSOR>(m_hIcon); }
void CDebuggerGUIDlg::OnClose() { ExitProcess(0); }


LRESULT CDebuggerGUIDlg::OnDebugEvent(WPARAM wParam, LPARAM lParam)
{
	int eventType = (int)wParam;
	DWORD dwThreadId = (DWORD)lParam;

	if (eventType == DBG_EVENT_PAUSED) {
		m_currentThreadId = dwThreadId;
		RegInfo regs = { 0 };
		if (dbg_GetRegs(dwThreadId, &regs)) {

			// 1. 更新寄存器 
			CListCtrl* pListRegs = (CListCtrl*)GetDlgItem(IDC_LIST_REGS);
			if (pListRegs) {
				pListRegs->DeleteAllItems();
				struct RegMap { const TCHAR* name; DWORD val; };
				RegMap regData[] = {
					{_T("EAX"), regs.eax}, {_T("ECX"), regs.ecx},
					{_T("EDX"), regs.edx}, {_T("EBX"), regs.ebx},
					{_T("ESP"), regs.esp}, {_T("EBP"), regs.ebp},
					{_T("ESI"), regs.esi}, {_T("EDI"), regs.edi},
					{_T("EIP"), regs.eip}, {_T("EFL"), regs.eflags}
				};
				for (int i = 0; i < 10; i++) {
					pListRegs->InsertItem(i, regData[i].name);
					CString strVal; strVal.Format(_T("%08X"), regData[i].val);
					pListRegs->SetItemText(i, 1, strVal);
				}
			}

			// 2. 堆栈视口完美追踪：ESP 自动居顶
			CListCtrl* pListStack = (CListCtrl*)GetDlgItem(IDC_LIST_STACK);
			if (pListStack && pListStack->GetSafeHwnd()) {
				int maxStackRows = 2000000;
				int centerStackRow = maxStackRows / 2;

				if (regs.esp < (DWORD)centerStackRow * 4) {
					m_stackBaseAddr = 0;
					centerStackRow = regs.esp / 4;
				}
				else {
					m_stackBaseAddr = regs.esp - (centerStackRow * 4);
				}

				pListStack->SetItemCountEx(maxStackRows, LVSICF_NOSCROLL);

				POSITION pos = pListStack->GetFirstSelectedItemPosition();
				while (pos) {
					int nItem = pListStack->GetNextSelectedItem(pos);
					pListStack->SetItemState(nItem, 0, LVIS_SELECTED | LVIS_FOCUSED);
				}
				pListStack->SetItemState(centerStackRow, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
				pListStack->EnsureVisible(centerStackRow, FALSE);
				pListStack->Invalidate();
			}

			// 3. 内存视口追踪
			CListCtrl* pListMem = (CListCtrl*)GetDlgItem(IDC_LIST_MEMORY);
			if (pListMem && pListMem->GetSafeHwnd()) {
				int maxMemRows = 2000000;
				int centerMemRow = maxMemRows / 2;

				if (m_currentDumpAddr < (DWORD)centerMemRow * 16) {
					m_memoryBaseAddr = 0;
					centerMemRow = m_currentDumpAddr / 16;
				}
				else {
					m_memoryBaseAddr = m_currentDumpAddr - (centerMemRow * 16);
				}

				pListMem->SetItemCountEx(maxMemRows, LVSICF_NOSCROLL);
				pListMem->EnsureVisible(centerMemRow, FALSE);
				pListMem->Invalidate();
			}

			// 4. 反汇编高亮逻辑
			dbg_EnsureDisasm(regs.eip);
			CListCtrl* pList = (CListCtrl*)GetDlgItem(IDC_LIST_DISASM);
			if (pList && pList->GetSafeHwnd()) {
				m_currentEIP = regs.eip;
				int totalInstrs = dbg_GetGlobalDisasmCount();
				pList->SetItemCountEx(totalInstrs, LVSICF_NOSCROLL);
				int index = dbg_FindDisasmIndexByAddr(regs.eip);

				POSITION pos = pList->GetFirstSelectedItemPosition();
				while (pos) {
					int nItem = pList->GetNextSelectedItem(pos);
					pList->SetItemState(nItem, 0, LVIS_SELECTED | LVIS_FOCUSED);
				}

				if (index != -1) {
					pList->SetItemState(index, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
					int nTop = pList->GetTopIndex();
					int nPage = pList->GetCountPerPage();

					if (index <= nTop || index >= nTop + nPage - 1) {
						int targetTop = index;
						int currentTop = pList->GetTopIndex();
						if (currentTop != targetTop) {
							CRect rc; pList->GetItemRect(0, &rc, LVIR_BOUNDS);
							pList->Scroll(CSize(0, (targetTop - currentTop) * rc.Height()));
						}
					}
					else { pList->EnsureVisible(index, FALSE); }
				}
				pList->Invalidate(); pList->SetFocus();
			}
		}
	}
	else if (eventType == DBG_EVENT_EXITED) {
		CListCtrl* pListDisasm = (CListCtrl*)GetDlgItem(IDC_LIST_DISASM);
		if (pListDisasm) pListDisasm->SetItemCountEx(0);

		CListCtrl* pListStack = (CListCtrl*)GetDlgItem(IDC_LIST_STACK);
		if (pListStack) pListStack->SetItemCountEx(0);

		CListCtrl* pListMem = (CListCtrl*)GetDlgItem(IDC_LIST_MEMORY);
		if (pListMem) pListMem->SetItemCountEx(0);

		CListCtrl* pListRegs = (CListCtrl*)GetDlgItem(IDC_LIST_REGS);
		if (pListRegs) { pListRegs->DeleteAllItems(); pListRegs->InsertItem(0, _T("Status")); pListRegs->SetItemText(0, 1, _T("程序已退出")); }
	}
	return 0;
}

void CDebuggerGUIDlg::OnBnClickedBtnStart()
{
	bool bRet = dbg_Start(L"CRACKME.EXE", MyDebuggerCallback);
	if (bRet) GetDlgItem(IDC_BTN_START)->EnableWindow(FALSE);
	else AfxMessageBox(_T("启动调试失败！请检查目标程序是否存在。"));
}

void CDebuggerGUIDlg::OnBnClickedBtnStepIn() { dbg_StepInto(); }
void CDebuggerGUIDlg::OnBnClickedBtnRun() { dbg_Go(); }
void CDebuggerGUIDlg::OnBnClickedBtnStepOver() { dbg_StepOver(); }

void CDebuggerGUIDlg::OnBnClickedBtnSetBp()
{
	CString strAddr;
	GetDlgItemText(IDC_EDIT_BP_ADDR, strAddr);
	strAddr.Trim(); if (strAddr.IsEmpty()) return;
	strAddr.Replace(_T("0x"), _T("")); strAddr.Replace(_T("0X"), _T(""));

	DWORD dwAddr = _tcstoul(strAddr.GetString(), nullptr, 16);
	if (dwAddr == 0 && strAddr != _T("0") && strAddr != _T("00000000")) return;

	dbg_SetBreakpoint(dwAddr);
	CString msg; msg.Format(_T("软件断点已尝试设置在地址: 0x%08X"), dwAddr);
	AfxMessageBox(msg);
}

void CDebuggerGUIDlg::OnGetdispinfoListDisasm(NMHDR* pNMHDR, LRESULT* pResult)
{
	NMLVDISPINFO* pDispInfo = reinterpret_cast<NMLVDISPINFO*>(pNMHDR);
	LVITEM* pItem = &(pDispInfo->item);

	if (pItem->mask & LVIF_TEXT) {
		InstrInfo info;
		if (dbg_GetGlobalDisasmItem(pItem->iItem, &info)) {
			if (pItem->iSubItem == 0) {
				CString strAddr;
				if (info.address == m_currentEIP) strAddr.Format(_T("-> %08X"), info.address);
				else strAddr.Format(_T("   %08X"), info.address);
				_tcsncpy_s(pItem->pszText, pItem->cchTextMax, strAddr, _TRUNCATE);
			}
			else if (pItem->iSubItem == 1) {
				CString strHex(info.hexCode);
				_tcsncpy_s(pItem->pszText, pItem->cchTextMax, strHex, _TRUNCATE);
			}
			else if (pItem->iSubItem == 2) {
				CString strAsm(info.assembly);
				_tcsncpy_s(pItem->pszText, pItem->cchTextMax, strAsm, _TRUNCATE);
			}
			// 【核心修复 3】：把丢失的智能注释数据填充进去！
			else if (pItem->iSubItem == 3) {
				CString strCmt(info.comment);
				_tcsncpy_s(pItem->pszText, pItem->cchTextMax, strCmt, _TRUNCATE);
			}
		}
	}
	*pResult = 0;
}

void CDebuggerGUIDlg::OnGetdispinfoListMemory(NMHDR* pNMHDR, LRESULT* pResult)
{
	NMLVDISPINFO* pDispInfo = reinterpret_cast<NMLVDISPINFO*>(pNMHDR);
	LVITEM* pItem = &(pDispInfo->item);

	if (pItem->mask & LVIF_TEXT) {
		DWORD rowAddr = m_memoryBaseAddr + (pItem->iItem * 16);

		if (pItem->iSubItem == 0) {
			CString strAddr; strAddr.Format(_T("%08X"), rowAddr);
			_tcsncpy_s(pItem->pszText, pItem->cchTextMax, strAddr, _TRUNCATE);
		}
		else {
			BYTE memData[16] = { 0 };
			bool bRead = dbg_ReadMemory(rowAddr, memData, 16);

			if (pItem->iSubItem == 1) {
				CString strHex;
				if (bRead) {
					for (int j = 0; j < 16; j++) {
						CString tmp; tmp.Format(_T("%02X "), memData[j]);
						strHex += tmp;
						if (j == 7) strHex += _T("- ");
					}
				}
				else {
					strHex = _T("?? ?? ?? ?? ?? ?? ?? ?? - ?? ?? ?? ?? ?? ?? ?? ??");
				}
				_tcsncpy_s(pItem->pszText, pItem->cchTextMax, strHex, _TRUNCATE);
			}
			else if (pItem->iSubItem == 2) {
				CString strAscii;
				if (bRead) {
					for (int j = 0; j < 16; j++) {
						BYTE b = memData[j];
						if (b >= 32 && b <= 126) strAscii += (TCHAR)b;
						else strAscii += _T(".");
					}
				}
				_tcsncpy_s(pItem->pszText, pItem->cchTextMax, strAscii, _TRUNCATE);
			}
		}
	}
	*pResult = 0;
}

void CDebuggerGUIDlg::OnGetdispinfoListStack(NMHDR* pNMHDR, LRESULT* pResult)
{
	NMLVDISPINFO* pDispInfo = reinterpret_cast<NMLVDISPINFO*>(pNMHDR);
	LVITEM* pItem = &(pDispInfo->item);

	if (pItem->mask & LVIF_TEXT) {
		DWORD rowAddr = m_stackBaseAddr + (pItem->iItem * 4);

		if (pItem->iSubItem == 0) {
			CString strAddr; strAddr.Format(_T("%08X"), rowAddr);
			_tcsncpy_s(pItem->pszText, pItem->cchTextMax, strAddr, _TRUNCATE);
		}
		else {
			DWORD val = 0;
			bool bRead = dbg_ReadMemory(rowAddr, &val, 4);

			if (pItem->iSubItem == 1) {
				CString strVal;
				if (bRead) strVal.Format(_T("%08X"), val);
				else strVal = _T("????????");
				_tcsncpy_s(pItem->pszText, pItem->cchTextMax, strVal, _TRUNCATE);
			}
			else if (pItem->iSubItem == 2) {
				CString strComment;
				if (bRead) {
					char asciiBuf[5] = { 0 };
					memcpy(asciiBuf, &val, 4);
					for (int j = 0; j < 4; j++) {
						if (asciiBuf[j] < 32 || asciiBuf[j] > 126) asciiBuf[j] = '.';
					}
					strComment = asciiBuf;
				}
				_tcsncpy_s(pItem->pszText, pItem->cchTextMax, strComment, _TRUNCATE);
			}
		}
	}
	*pResult = 0;
}

void CDebuggerGUIDlg::OnCustomDrawListDisasm(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMLVCUSTOMDRAW pLVCD = reinterpret_cast<LPNMLVCUSTOMDRAW>(pNMHDR);
	*pResult = CDRF_DODEFAULT;

	if (pLVCD->nmcd.dwDrawStage == CDDS_PREPAINT) {
		*pResult = CDRF_NOTIFYITEMDRAW;
	}
	else if (pLVCD->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
		// 【神级修复】：强行剥夺系统的“深蓝色选中”绘制权！
		// 只要把这个状态清空，Windows 就不会画那个讨厌的深蓝底和白字了！
		pLVCD->nmcd.uItemState &= ~CDIS_SELECTED;
		*pResult = CDRF_NOTIFYSUBITEMDRAW;
	}
	else if (pLVCD->nmcd.dwDrawStage == (CDDS_ITEMPREPAINT | CDDS_SUBITEM)) {

		COLORREF textColor = RGB(0, 0, 0);       // 默认黑字
		COLORREF bgColor = RGB(255, 255, 255);   // 默认白底

		int rowIndex = (int)pLVCD->nmcd.dwItemSpec;

		InstrInfo info;
		if (dbg_GetGlobalDisasmItem(rowIndex, &info)) {

			// 1. 判断是否被用户鼠标选中：画上优雅的浅灰色
			CListCtrl* pList = (CListCtrl*)GetDlgItem(IDC_LIST_DISASM);
			if (pList->GetItemState(rowIndex, LVIS_SELECTED) == LVIS_SELECTED) {
				bgColor = RGB(225, 225, 225); // 选中时的浅灰色 (不会刺眼)
			}

			// 2. 判断是否下了断点：醒目的红色 (优先级高于选中时的浅灰)
			if (dbg_HasBreakpoint(info.address)) {
				bgColor = RGB(250, 100, 100); // 柔和的断点红底
				textColor = RGB(0, 0, 0);     // 黑色字体更清晰
			}

			// 3. 判断是否是当前执行到的 EIP！
			if (info.address == m_currentEIP) {
				// 【完美复刻 x64dbg】：只有第 0 列（地址列）变成原谅绿！
				if (pLVCD->iSubItem == 0) {
					bgColor = RGB(164, 250, 120); // x64dbg 同款浅绿色
					textColor = RGB(0, 0, 0);
				}
			}

			// 4. 汇编语法高亮 (仅处理第 2 列：汇编指令)
			if (pLVCD->iSubItem == 2) {
				CString asmStr(info.assembly);
				asmStr.MakeUpper();

				if (asmStr.Find(_T("CALL")) == 0) textColor = RGB(0, 0, 200);
				else if (asmStr.Find(_T("JMP")) == 0 || asmStr.Find(_T("J")) == 0) textColor = RGB(200, 0, 0);
				else if (asmStr.Find(_T("PUSH")) == 0 || asmStr.Find(_T("POP")) == 0 || asmStr.Find(_T("RET")) == 0) textColor = RGB(150, 0, 150);
				else if (asmStr.Find(_T("XOR")) == 0 || asmStr.Find(_T("SUB")) == 0 || asmStr.Find(_T("ADD")) == 0 || asmStr.Find(_T("INC")) == 0) textColor = RGB(0, 128, 0);
				else if (asmStr.Find(_T("INT3")) != -1 || asmStr.Find(_T("NOP")) != -1) textColor = RGB(128, 128, 128);
			}
		}

		// 把我们精心计算好的颜色告诉 Windows 画笔
		pLVCD->clrText = textColor;
		pLVCD->clrTextBk = bgColor;

		// 必须返回 CDRF_NEWFONT，告诉系统应用我们自定义的颜色！
		*pResult = CDRF_NEWFONT;
	}
}

void CDebuggerGUIDlg::OnNMDblclkListRegs(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	*pResult = 0;

	int row = pNMItemActivate->iItem;
	if (row < 0 || m_currentThreadId == 0) return;

	CListCtrl* pList = (CListCtrl*)GetDlgItem(IDC_LIST_REGS);
	CString regName = pList->GetItemText(row, 0);
	CString regVal = pList->GetItemText(row, 1);

	CEditRegDlg dlg;
	dlg.m_strRegName = regName;
	dlg.m_strRegValue = regVal;

	if (dlg.DoModal() == IDOK) {
		DWORD newVal = _tcstoul(dlg.m_strRegValue, nullptr, 16);
		char ansiName[16] = { 0 };
		WideCharToMultiByte(CP_ACP, 0, regName, -1, ansiName, 16, NULL, NULL);

		if (dbg_SetRegister(m_currentThreadId, ansiName, newVal)) {
			CString newStr; newStr.Format(_T("%08X"), newVal);
			pList->SetItemText(row, 1, newStr);

			if (regName == _T("EIP")) {
				dbg_EnsureDisasm(newVal);
				CListCtrl* pDisasm = (CListCtrl*)GetDlgItem(IDC_LIST_DISASM);
				pDisasm->SetItemCountEx(dbg_GetGlobalDisasmCount(), LVSICF_NOSCROLL);
				int newIndex = dbg_FindDisasmIndexByAddr(newVal);
				if (newIndex != -1) {
					POSITION pos = pDisasm->GetFirstSelectedItemPosition();
					while (pos) {
						int nItem = pDisasm->GetNextSelectedItem(pos);
						pDisasm->SetItemState(nItem, 0, LVIS_SELECTED | LVIS_FOCUSED);
					}
					pDisasm->SetItemState(newIndex, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
					pDisasm->EnsureVisible(newIndex, FALSE);
				}
				pDisasm->Invalidate(); pDisasm->SetFocus();
			}
		}
		else { AfxMessageBox(_T("修改底层寄存器失败！")); }
	}
}

// ========================================================
// 【黑科技核心】：纯代码手搓十字动态分割视口！
// ========================================================

void CDebuggerGUIDlg::OnSize(UINT nType, int cx, int cy)
{
	CDialogEx::OnSize(nType, cx, cy);
	if (cx <= 0 || cy <= 0) return;
	CWnd* pDisasm = GetDlgItem(IDC_LIST_DISASM);
	if (!pDisasm || !pDisasm->GetSafeHwnd()) return;

	if (GetDlgItem(IDOK)) GetDlgItem(IDOK)->ShowWindow(SW_HIDE);
	if (GetDlgItem(IDCANCEL)) GetDlgItem(IDCANCEL)->ShowWindow(SW_HIDE);

	int topBarHeight = 55;

	// 1. 初始化分割线位置 (第一次运行时)
	if (m_nSplitterX == 0) m_nSplitterX = cx - 350;
	if (m_nSplitterY == 0) m_nSplitterY = topBarHeight + (cy - topBarHeight) * 2 / 3;

	// 2. 边界保护：防止把窗口拉到屏幕外导致崩溃
	if (m_nSplitterX < 150) m_nSplitterX = 150;
	if (m_nSplitterX > cx - 150) m_nSplitterX = cx - 150;
	if (m_nSplitterY < topBarHeight + 100) m_nSplitterY = topBarHeight + 100;
	if (m_nSplitterY > cy - 100) m_nSplitterY = cy - 100;

	// 顶部按钮横向排列
	int btnX = 10, btnY = 12, btnW = 80, btnH = 30, spacing = 10;
	auto moveCtrl = [&](int id, int& x, int w) {
		CWnd* pWnd = GetDlgItem(id);
		if (pWnd) { pWnd->MoveWindow(x, btnY, w, btnH); x += w + spacing; }
		};
	moveCtrl(IDC_BTN_START, btnX, btnW);
	moveCtrl(IDC_BTN_STEP_IN, btnX, btnW);
	moveCtrl(IDC_BTN_STEP_OVER, btnX, btnW);
	moveCtrl(IDC_BTN_RUN, btnX, btnW);
	CWnd* pEditBp = GetDlgItem(IDC_EDIT_BP_ADDR);
	if (pEditBp) { pEditBp->MoveWindow(btnX, btnY + 5, 80, 20); btnX += 80 + spacing; }
	CWnd* pBtnSetBp = GetDlgItem(IDC_BTN_SET_BP);
	if (pBtnSetBp) { pBtnSetBp->MoveWindow(btnX, btnY, 100, btnH); }

	int sp = 3; // 留给分割线的缝隙宽度 (左右各留3像素，拼起来就是一条缝)

	// 左上：反汇编 (依赖 m_nSplitterX 和 m_nSplitterY)
	pDisasm->MoveWindow(5, topBarHeight, m_nSplitterX - 5 - sp, m_nSplitterY - topBarHeight - sp);

	// 左下：内存
	CWnd* pMemory = GetDlgItem(IDC_LIST_MEMORY);
	if (pMemory) pMemory->MoveWindow(5, m_nSplitterY + sp, m_nSplitterX - 5 - sp, cy - m_nSplitterY - sp - 5);

	// 右上：寄存器
	CWnd* pRegs = GetDlgItem(IDC_LIST_REGS);
	if (pRegs) pRegs->MoveWindow(m_nSplitterX + sp, topBarHeight, cx - m_nSplitterX - sp - 5, m_nSplitterY - topBarHeight - sp);

	// 右下：堆栈
	CWnd* pStack = GetDlgItem(IDC_LIST_STACK);
	if (pStack) pStack->MoveWindow(m_nSplitterX + sp, m_nSplitterY + sp, cx - m_nSplitterX - sp - 5, cy - m_nSplitterY - sp - 5);
}

// 鼠标按下：判断是否点中了中间的缝隙
void CDebuggerGUIDlg::OnLButtonDown(UINT nFlags, CPoint point)
{
	CRect rectClient;
	GetClientRect(&rectClient);

	int sp = 4;
	CRect rectSplitterX(m_nSplitterX - sp, 55, m_nSplitterX + sp, rectClient.bottom);
	CRect rectSplitterY(0, m_nSplitterY - sp, rectClient.right, m_nSplitterY + sp);

	bool bHitX = rectSplitterX.PtInRect(point);
	bool bHitY = rectSplitterY.PtInRect(point);

	if (bHitX || bHitY) {
		m_bDraggingX = bHitX;
		m_bDraggingY = bHitY;
		SetCapture(); // 捕获鼠标，这样拖到窗外也不会丢失事件
	}
	CDialogEx::OnLButtonDown(nFlags, point);
}

// 鼠标松开：结束拖拽
void CDebuggerGUIDlg::OnLButtonUp(UINT nFlags, CPoint point)
{
	if (m_bDraggingX || m_bDraggingY) {
		m_bDraggingX = false;
		m_bDraggingY = false;
		ReleaseCapture();
	}
	CDialogEx::OnLButtonUp(nFlags, point);
}

// 鼠标移动：如果是拖拽状态，实时改变坐标并重排！
void CDebuggerGUIDlg::OnMouseMove(UINT nFlags, CPoint point)
{
	if (m_bDraggingX || m_bDraggingY) {
		if (m_bDraggingX) m_nSplitterX = point.x;
		if (m_bDraggingY) m_nSplitterY = point.y;

		CRect rect; GetClientRect(&rect);
		OnSize(0, rect.Width(), rect.Height()); // 实时重新排版
	}
	CDialogEx::OnMouseMove(nFlags, point);
}

// 设置光标：当鼠标悬停在缝隙上时，变成拉伸箭头！
BOOL CDebuggerGUIDlg::OnSetCursor(CWnd* pWnd, UINT nHitTest, UINT message)
{
	// 【极其重要的安全修复】：
	// 只有当鼠标真的停在“对话框背景”上时，我们才去接管十字指针！
	// 如果鼠标放在了列表的表头上（pWnd 不是 this），直接放行，把改变列宽的权力还给系统！
	if (pWnd == this) {
		CPoint point;
		GetCursorPos(&point);
		ScreenToClient(&point);

		CRect rectClient;
		GetClientRect(&rectClient);

		int sp = 4;
		CRect rectSplitterX(m_nSplitterX - sp, 45, m_nSplitterX + sp, rectClient.bottom);
		CRect rectSplitterY(0, m_nSplitterY - sp, rectClient.right, m_nSplitterY + sp);

		bool bHitX = rectSplitterX.PtInRect(point);
		bool bHitY = rectSplitterY.PtInRect(point);

		if (bHitX && bHitY) {
			SetCursor(AfxGetApp()->LoadStandardCursor(IDC_SIZEALL)); // 十字箭头
			return TRUE;
		}
		else if (bHitX) {
			SetCursor(AfxGetApp()->LoadStandardCursor(IDC_SIZEWE)); // 左右箭头
			return TRUE;
		}
		else if (bHitY) {
			SetCursor(AfxGetApp()->LoadStandardCursor(IDC_SIZENS)); // 上下箭头
			return TRUE;
		}
	}

	return CDialogEx::OnSetCursor(pWnd, nHitTest, message);
}

// ========================================================
// 黑科技：拦截 F2 快捷键，实现 OD 级一键下断！
// ========================================================
BOOL CDebuggerGUIDlg::PreTranslateMessage(MSG* pMsg)
{
	// 拦截按键事件，检测是否按下了 F2
	if (pMsg->message == WM_KEYDOWN && pMsg->wParam == VK_F2) {
		CWnd* pFocus = GetFocus();
		CWnd* pList = GetDlgItem(IDC_LIST_DISASM);

		// 只有当用户正把鼠标焦点放在【反汇编列表】里时，F2 才生效
		if (pFocus && pList && pFocus->GetSafeHwnd() == pList->GetSafeHwnd()) {
			CListCtrl* pListCtrl = (CListCtrl*)pList;
			POSITION pos = pListCtrl->GetFirstSelectedItemPosition();
			if (pos) {
				int nItem = pListCtrl->GetNextSelectedItem(pos);

				// 提取那一行代码的地址
				CString strAddr = pListCtrl->GetItemText(nItem, 0);
				strAddr.Replace(_T("->"), _T(""));
				strAddr.Trim();
				DWORD addr = _tcstoul(strAddr, nullptr, 16);

				if (addr != 0) {
					// 【核心逻辑】：有断点就取消，没断点就下断！
					if (dbg_HasBreakpoint(addr)) {
						dbg_RemoveBreakpoint(addr);
					}
					else {
						dbg_SetBreakpoint(addr);
					}
					// 强制刷新列表，让红色瞬间显现！
					pListCtrl->Invalidate();
				}
			}
			return TRUE; // 拦截成功，不要把这个按键传给系统了
		}
	}
	return CDialogEx::PreTranslateMessage(pMsg);
}