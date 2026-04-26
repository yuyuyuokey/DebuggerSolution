#include "pch.h"
#include "framework.h"
#include "DebuggerGUI.h"
#include "DebuggerGUIDlg.h"
#include "afxdialogex.h"
#include "DebuggerAPI.h"
#include "CEditRegDlg.h"
#include "CProcessListDlg.h"

HWND g_hMainWnd = NULL;

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

void __stdcall MyDebuggerCallback(int eventType, DWORD dwThreadId)
{
	if (g_hMainWnd)
	{
		::PostMessage(g_hMainWnd, WM_DEBUG_EVENT, (WPARAM)eventType, (LPARAM)dwThreadId);
	}
}

CDebuggerGUIDlg::CDebuggerGUIDlg(CWnd* pParent) : CDialogEx(IDD_DEBUGGERGUI_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CDebuggerGUIDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_TAB_MAIN, m_tabMain);
}

BEGIN_MESSAGE_MAP(CDebuggerGUIDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_MESSAGE(WM_DEBUG_EVENT, &CDebuggerGUIDlg::OnDebugEvent)
	ON_WM_CLOSE()
	ON_WM_SIZE()

	ON_COMMAND(ID_FILE_OPEN, &CDebuggerGUIDlg::OnFileOpen)
	ON_COMMAND(ID_FILE_ATTACH, &CDebuggerGUIDlg::OnFileAttach)

	ON_COMMAND(ID_VIEW_CPU, &CDebuggerGUIDlg::OnViewCpu)
	ON_COMMAND(ID_VIEW_BP, &CDebuggerGUIDlg::OnViewBreakpoints)
	ON_COMMAND(ID_VIEW_MEMMAP, &CDebuggerGUIDlg::OnViewMemmap)
	ON_COMMAND(ID_VIEW_CALLSTACK, &CDebuggerGUIDlg::OnViewCallstack)

	ON_COMMAND(ID_DBG_RUN, &CDebuggerGUIDlg::OnDbgRun)
	ON_COMMAND(ID_DBG_STEPIN, &CDebuggerGUIDlg::OnDbgStepIn)
	ON_COMMAND(ID_DBG_STEPOVER, &CDebuggerGUIDlg::OnDbgStepOver)

	ON_NOTIFY(LVN_GETDISPINFO, IDC_LIST_DISASM, &CDebuggerGUIDlg::OnGetdispinfoListDisasm)
	ON_NOTIFY(LVN_GETDISPINFO, IDC_LIST_MEMORY, &CDebuggerGUIDlg::OnGetdispinfoListMemory)
	ON_NOTIFY(LVN_GETDISPINFO, IDC_LIST_STACK, &CDebuggerGUIDlg::OnGetdispinfoListStack)

	ON_NOTIFY(LVN_GETDISPINFO, IDC_LIST_BPS, &CDebuggerGUIDlg::OnGetdispinfoListBPs)
	ON_NOTIFY(LVN_GETDISPINFO, IDC_LIST_MMAP, &CDebuggerGUIDlg::OnGetdispinfoListMMap)
	ON_NOTIFY(LVN_GETDISPINFO, IDC_LIST_CSTACK, &CDebuggerGUIDlg::OnGetdispinfoListCStack)

	ON_NOTIFY(NM_CUSTOMDRAW, IDC_LIST_DISASM, &CDebuggerGUIDlg::OnCustomDrawListDisasm)
	ON_NOTIFY(NM_DBLCLK, IDC_LIST_REGS, &CDebuggerGUIDlg::OnNMDblclkListRegs)

	// 右键菜单响应
	ON_NOTIFY(NM_RCLICK, IDC_LIST_DISASM, &CDebuggerGUIDlg::OnNMRClickListDisasm)

	ON_NOTIFY(TCN_SELCHANGE, IDC_TAB_MAIN, &CDebuggerGUIDlg::OnTcnSelchangeTabMain)

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

	SetWindowText(_T("Debugger_Gemini - x86 Reverse Engine Framework : [Idle]"));

	if (m_tabMain.GetSafeHwnd())
	{
		m_tabMain.InsertItem(TAB_CPU, _T("CPU"));
		m_tabMain.InsertItem(TAB_BREAKPOINTS, _T("断点"));
		m_tabMain.InsertItem(TAB_MEMMAP, _T("内存布局"));
		m_tabMain.InsertItem(TAB_CALLSTACK, _T("调用堆栈"));
	}

	CListCtrl* pListDisasm = (CListCtrl*)GetDlgItem(IDC_LIST_DISASM);
	if (pListDisasm)
	{
		pListDisasm->SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_HEADERDRAGDROP);
		pListDisasm->InsertColumn(0, _T("地址"), LVCFMT_LEFT, 110);
		pListDisasm->InsertColumn(1, _T("机器码"), LVCFMT_LEFT, 160);
		pListDisasm->InsertColumn(2, _T("汇编指令"), LVCFMT_LEFT, 250);
		pListDisasm->InsertColumn(3, _T("注释"), LVCFMT_LEFT, 350);
	}

	CRect rectZero(0, 0, 0, 0);
	DWORD dwStyle = WS_CHILD | WS_BORDER | LVS_REPORT | LVS_OWNERDATA;

	m_listBreakpoints.Create(dwStyle, rectZero, this, IDC_LIST_BPS);
	m_listBreakpoints.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	m_listBreakpoints.InsertColumn(0, _T("类型"), LVCFMT_LEFT, 80);
	m_listBreakpoints.InsertColumn(1, _T("地址"), LVCFMT_LEFT, 110);
	m_listBreakpoints.InsertColumn(2, _T("模块/标签"), LVCFMT_LEFT, 150);
	m_listBreakpoints.InsertColumn(3, _T("状态"), LVCFMT_LEFT, 80);

	m_listMemMap.Create(dwStyle, rectZero, this, IDC_LIST_MMAP);
	m_listMemMap.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	m_listMemMap.InsertColumn(0, _T("地址"), LVCFMT_LEFT, 110);
	m_listMemMap.InsertColumn(1, _T("大小"), LVCFMT_LEFT, 110);
	m_listMemMap.InsertColumn(2, _T("信息 (模块)"), LVCFMT_LEFT, 200);
	m_listMemMap.InsertColumn(3, _T("页面保护"), LVCFMT_LEFT, 100);
	m_listMemMap.InsertColumn(4, _T("初始保护"), LVCFMT_LEFT, 100);

	m_listCallStack.Create(dwStyle, rectZero, this, IDC_LIST_CSTACK);
	m_listCallStack.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	m_listCallStack.InsertColumn(0, _T("地址 (EBP)"), LVCFMT_LEFT, 110);
	m_listCallStack.InsertColumn(1, _T("返回到"), LVCFMT_LEFT, 110);
	m_listCallStack.InsertColumn(2, _T("注释 (模块)"), LVCFMT_LEFT, 250);

	CListCtrl* pListRegs = (CListCtrl*)GetDlgItem(IDC_LIST_REGS);
	if (pListRegs)
	{
		pListRegs->SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_HEADERDRAGDROP);
		pListRegs->InsertColumn(0, _T("寄存器"), LVCFMT_LEFT, 75);
		pListRegs->InsertColumn(1, _T("数据值"), LVCFMT_LEFT, 120);
	}

	CListCtrl* pListStack = (CListCtrl*)GetDlgItem(IDC_LIST_STACK);
	if (pListStack)
	{
		pListStack->SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_HEADERDRAGDROP);
		pListStack->InsertColumn(0, _T("地址"), LVCFMT_LEFT, 110);
		pListStack->InsertColumn(1, _T("数值"), LVCFMT_LEFT, 100);
		pListStack->InsertColumn(2, _T("注释"), LVCFMT_LEFT, 200);
	}

	CListCtrl* pListMemory = (CListCtrl*)GetDlgItem(IDC_LIST_MEMORY);
	if (pListMemory)
	{
		pListMemory->SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_HEADERDRAGDROP);
		pListMemory->InsertColumn(0, _T("地址"), LVCFMT_LEFT, 110);
		pListMemory->InsertColumn(1, _T("Hex 数据"), LVCFMT_LEFT, 330);
		pListMemory->InsertColumn(2, _T("ASCII"), LVCFMT_LEFT, 150);
	}

	SwitchTab(TAB_CPU);

	ShowWindow(SW_SHOWMAXIMIZED);
	return TRUE;
}

void CDebuggerGUIDlg::OnTcnSelchangeTabMain(NMHDR* pNMHDR, LRESULT* pResult)
{
	int sel = m_tabMain.GetCurSel();
	SwitchTab(sel);
	*pResult = 0;
}

void CDebuggerGUIDlg::SwitchTab(int tabIndex)
{
	if (m_tabMain.GetSafeHwnd())
	{
		m_tabMain.SetCurSel(tabIndex);
	}

	CWnd* pListDisasm = GetDlgItem(IDC_LIST_DISASM);
	if (pListDisasm)
	{
		if (tabIndex == TAB_CPU)
			pListDisasm->ShowWindow(SW_SHOW);
		else
			pListDisasm->ShowWindow(SW_HIDE);
	}

	if (tabIndex == TAB_BREAKPOINTS) m_listBreakpoints.ShowWindow(SW_SHOW); else m_listBreakpoints.ShowWindow(SW_HIDE);
	if (tabIndex == TAB_MEMMAP) m_listMemMap.ShowWindow(SW_SHOW); else m_listMemMap.ShowWindow(SW_HIDE);
	if (tabIndex == TAB_CALLSTACK) m_listCallStack.ShowWindow(SW_SHOW); else m_listCallStack.ShowWindow(SW_HIDE);

	if (tabIndex == TAB_BREAKPOINTS)
	{
		RefreshBreakpointsTab();
	}
	else if (tabIndex == TAB_MEMMAP)
	{
		dbg_UpdateMemoryMap();
		m_listMemMap.SetItemCountEx(dbg_GetMemoryMapCount(), LVSICF_NOSCROLL);
		m_listMemMap.Invalidate();
	}
	else if (tabIndex == TAB_CALLSTACK)
	{
		dbg_UpdateCallStack(m_currentThreadId);
		m_listCallStack.SetItemCountEx(dbg_GetCallStackCount(), LVSICF_NOSCROLL);
		m_listCallStack.Invalidate();
	}
}

void CDebuggerGUIDlg::RefreshBreakpointsTab()
{
	m_listBreakpoints.SetItemCountEx(dbg_GetTotalBPCount(), LVSICF_NOSCROLL);
	m_listBreakpoints.Invalidate();
}

void CDebuggerGUIDlg::OnViewCpu() { SwitchTab(TAB_CPU); }
void CDebuggerGUIDlg::OnViewBreakpoints() { SwitchTab(TAB_BREAKPOINTS); }
void CDebuggerGUIDlg::OnViewMemmap() { SwitchTab(TAB_MEMMAP); }
void CDebuggerGUIDlg::OnViewCallstack() { SwitchTab(TAB_CALLSTACK); }

void CDebuggerGUIDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this);
		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

HCURSOR CDebuggerGUIDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CDebuggerGUIDlg::OnClose()
{
	ExitProcess(0);
}

LRESULT CDebuggerGUIDlg::OnDebugEvent(WPARAM wParam, LPARAM lParam)
{
	int eventType = (int)wParam;
	DWORD dwThreadId = (DWORD)lParam;

	if (eventType == DBG_EVENT_PAUSED)
	{
		m_currentThreadId = dwThreadId;
		RegInfo regs = { 0 };

		if (dbg_GetRegs(dwThreadId, &regs))
		{
			CListCtrl* pListRegs = (CListCtrl*)GetDlgItem(IDC_LIST_REGS);
			if (pListRegs)
			{
				pListRegs->DeleteAllItems();
				struct RegMap { const TCHAR* name; DWORD val; };
				RegMap regData[] = {
					{_T("EAX"), regs.eax}, {_T("ECX"), regs.ecx}, {_T("EDX"), regs.edx}, {_T("EBX"), regs.ebx},
					{_T("ESP"), regs.esp}, {_T("EBP"), regs.ebp}, {_T("ESI"), regs.esi}, {_T("EDI"), regs.edi},
					{_T("EIP"), regs.eip}, {_T("EFL"), regs.eflags}
				};

				for (int i = 0; i < 10; i++)
				{
					pListRegs->InsertItem(i, regData[i].name);
					CString strVal;
					strVal.Format(_T("%08X"), regData[i].val);
					pListRegs->SetItemText(i, 1, strVal);
				}
			}

			CListCtrl* pListStack = (CListCtrl*)GetDlgItem(IDC_LIST_STACK);
			if (pListStack && pListStack->GetSafeHwnd())
			{
				int maxStackRows = 2000000;
				int centerStackRow = maxStackRows / 2;

				if (regs.esp < (DWORD)centerStackRow * 4)
				{
					m_stackBaseAddr = 0;
					centerStackRow = regs.esp / 4;
				}
				else
				{
					m_stackBaseAddr = regs.esp - (centerStackRow * 4);
				}

				pListStack->SetItemCountEx(maxStackRows, LVSICF_NOSCROLL);
				POSITION pos = pListStack->GetFirstSelectedItemPosition();

				while (pos)
				{
					int nItem = pListStack->GetNextSelectedItem(pos);
					pListStack->SetItemState(nItem, 0, LVIS_SELECTED | LVIS_FOCUSED);
				}

				pListStack->SetItemState(centerStackRow, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);

				if (pListStack->GetTopIndex() != centerStackRow)
				{
					CRect rc;
					pListStack->GetItemRect(0, &rc, LVIR_BOUNDS);
					pListStack->Scroll(CSize(0, (centerStackRow - pListStack->GetTopIndex()) * rc.Height()));
				}
				pListStack->Invalidate();
			}

			CListCtrl* pListMem = (CListCtrl*)GetDlgItem(IDC_LIST_MEMORY);
			if (pListMem && pListMem->GetSafeHwnd())
			{
				int maxMemRows = 2000000;
				int centerMemRow = maxMemRows / 2;

				if (m_currentDumpAddr < (DWORD)centerMemRow * 16)
				{
					m_memoryBaseAddr = 0;
					centerMemRow = m_currentDumpAddr / 16;
				}
				else
				{
					m_memoryBaseAddr = m_currentDumpAddr - (centerMemRow * 16);
				}

				pListMem->SetItemCountEx(maxMemRows, LVSICF_NOSCROLL);

				if (pListMem->GetTopIndex() != centerMemRow)
				{
					CRect rc;
					pListMem->GetItemRect(0, &rc, LVIR_BOUNDS);
					pListMem->Scroll(CSize(0, (centerMemRow - pListMem->GetTopIndex()) * rc.Height()));
				}
				pListMem->Invalidate();
			}

			dbg_EnsureDisasm(regs.eip);
			CListCtrl* pList = (CListCtrl*)GetDlgItem(IDC_LIST_DISASM);
			if (pList && pList->GetSafeHwnd())
			{
				m_currentEIP = regs.eip;
				int totalInstrs = dbg_GetGlobalDisasmCount();
				pList->SetItemCountEx(totalInstrs, LVSICF_NOSCROLL);

				int index = dbg_FindDisasmIndexByAddr(regs.eip);
				POSITION pos = pList->GetFirstSelectedItemPosition();

				while (pos)
				{
					int nItem = pList->GetNextSelectedItem(pos);
					pList->SetItemState(nItem, 0, LVIS_SELECTED | LVIS_FOCUSED);
				}

				if (index != -1)
				{
					pList->SetItemState(index, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
					int nTop = pList->GetTopIndex();
					int nPage = pList->GetCountPerPage();

					if (index <= nTop || index >= nTop + nPage - 1)
					{
						int targetTop = index;
						int currentTop = pList->GetTopIndex();
						if (currentTop != targetTop)
						{
							CRect rc;
							pList->GetItemRect(0, &rc, LVIR_BOUNDS);
							pList->Scroll(CSize(0, (targetTop - currentTop) * rc.Height()));
						}
					}
					else
					{
						pList->EnsureVisible(index, FALSE);
					}
				}
				pList->Invalidate();
				pList->SetFocus();
			}

			int currentTab = m_tabMain.GetCurSel();
			if (currentTab == TAB_BREAKPOINTS)
			{
				RefreshBreakpointsTab();
			}
			else if (currentTab == TAB_MEMMAP)
			{
				dbg_UpdateMemoryMap();
				m_listMemMap.SetItemCountEx(dbg_GetMemoryMapCount(), LVSICF_NOSCROLL);
				m_listMemMap.Invalidate();
			}
			else if (currentTab == TAB_CALLSTACK)
			{
				dbg_UpdateCallStack(m_currentThreadId);
				m_listCallStack.SetItemCountEx(dbg_GetCallStackCount(), LVSICF_NOSCROLL);
				m_listCallStack.Invalidate();
			}
		}
	}
	else if (eventType == DBG_EVENT_EXITED)
	{
		SetWindowText(_T("Debugger_Gemini - 调试已断开 / 目标进程已退出 [Status: Dead]"));

		CListCtrl* pListDisasm = (CListCtrl*)GetDlgItem(IDC_LIST_DISASM);
		if (pListDisasm) pListDisasm->SetItemCountEx(0);

		CListCtrl* pListStack = (CListCtrl*)GetDlgItem(IDC_LIST_STACK);
		if (pListStack) pListStack->SetItemCountEx(0);

		CListCtrl* pListMem = (CListCtrl*)GetDlgItem(IDC_LIST_MEMORY);
		if (pListMem) pListMem->SetItemCountEx(0);

		CListCtrl* pListRegs = (CListCtrl*)GetDlgItem(IDC_LIST_REGS);
		if (pListRegs)
		{
			pListRegs->DeleteAllItems();
		}

		m_listBreakpoints.SetItemCountEx(0);
		m_listMemMap.SetItemCountEx(0);
		m_listCallStack.SetItemCountEx(0);
	}
	return 0;
}

void CDebuggerGUIDlg::OnFileOpen()
{
	CFileDialog fileDlg(TRUE, _T("exe"), NULL, OFN_HIDEREADONLY | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR,
		_T("Win32 应用程序(*.exe)|*.exe|动态链接库 (*.dll)|*.dll|所有文件 (*.*)|*.*||"), this);

	if (fileDlg.DoModal() == IDOK)
	{
		CString strPath = fileDlg.GetPathName();
		bool bRet = dbg_Start(strPath.GetBuffer(), MyDebuggerCallback);

		if (bRet)
		{
			CString strTitle;
			strTitle.Format(_T("Debugger_Gemini - [调试中]: %s"), fileDlg.GetFileTitle());
			SetWindowText(strTitle);
		}
		else
		{
			AfxMessageBox(_T("引擎启动失败。"));
		}
	}
}

void CDebuggerGUIDlg::OnFileAttach()
{
	CProcessListDlg dlg;

	if (dlg.DoModal() == IDOK)
	{
		if (dlg.m_selectedPID == 0) return;
		bool bRet = dbg_Attach(dlg.m_selectedPID, MyDebuggerCallback);

		if (bRet)
		{
			CString strTitle;
			strTitle.Format(_T("Debugger_Gemini - [已附加 PID: %d]"), dlg.m_selectedPID);
			SetWindowText(strTitle);
		}
		else
		{
			AfxMessageBox(_T("附加失败。"));
		}
	}
}

void CDebuggerGUIDlg::OnDbgRun() { dbg_Go(); }
void CDebuggerGUIDlg::OnDbgStepIn() { dbg_StepInto(); }
void CDebuggerGUIDlg::OnDbgStepOver() { dbg_StepOver(); }
void CDebuggerGUIDlg::OnDbgPause() { dbg_Pause(); }
void CDebuggerGUIDlg::OnDbgStop() { dbg_Stop(); }
void CDebuggerGUIDlg::OnDbgRestart() { dbg_Restart(); }
void CDebuggerGUIDlg::OnDbgRunToReturn() { dbg_RunToReturn(); }
void CDebuggerGUIDlg::OnDbgRunToUserCode() { dbg_RunToUserCode(); }

void CDebuggerGUIDlg::OnDbgRunToCursor()
{
	CListCtrl* pList = (CListCtrl*)GetDlgItem(IDC_LIST_DISASM);
	if (!pList) return;

	POSITION pos = pList->GetFirstSelectedItemPosition();

	if (pos)
	{
		int nItem = pList->GetNextSelectedItem(pos);
		InstrInfo info;

		if (dbg_GetGlobalDisasmItem(nItem, &info))
		{
			dbg_RunToCursor(info.address);
		}
	}
}

void CDebuggerGUIDlg::OnGetdispinfoListDisasm(NMHDR* pNMHDR, LRESULT* pResult)
{
	NMLVDISPINFO* pDispInfo = reinterpret_cast<NMLVDISPINFO*>(pNMHDR);
	LVITEM* pItem = &(pDispInfo->item);

	if (pItem->mask & LVIF_TEXT)
	{
		InstrInfo info;
		if (dbg_GetGlobalDisasmItem(pItem->iItem, &info))
		{
			if (pItem->iSubItem == 0)
			{
				CString strAddr;
				if (info.address == m_currentEIP)
				{
					strAddr.Format(_T("-> %08X"), info.address);
				}
				else
				{
					strAddr.Format(_T("   %08X"), info.address);
				}
				_tcsncpy_s(pItem->pszText, pItem->cchTextMax, strAddr, _TRUNCATE);
			}
			else if (pItem->iSubItem == 1)
			{
				CString strHex(info.hexCode);
				_tcsncpy_s(pItem->pszText, pItem->cchTextMax, strHex, _TRUNCATE);
			}
			else if (pItem->iSubItem == 2)
			{
				CString strAsm(info.assembly);
				_tcsncpy_s(pItem->pszText, pItem->cchTextMax, strAsm, _TRUNCATE);
			}
			else if (pItem->iSubItem == 3)
			{
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

	if (pItem->mask & LVIF_TEXT)
	{
		DWORD rowAddr = m_memoryBaseAddr + (pItem->iItem * 16);

		if (pItem->iSubItem == 0)
		{
			CString strAddr;
			strAddr.Format(_T("%08X"), rowAddr);
			_tcsncpy_s(pItem->pszText, pItem->cchTextMax, strAddr, _TRUNCATE);
		}
		else
		{
			BYTE memData[16] = { 0 };
			bool bRead = dbg_ReadMemory(rowAddr, memData, 16);

			if (pItem->iSubItem == 1)
			{
				CString strHex;
				if (bRead)
				{
					for (int j = 0; j < 16; j++)
					{
						CString tmp;
						tmp.Format(_T("%02X "), memData[j]);
						strHex += tmp;
						if (j == 7)
						{
							strHex += _T("- ");
						}
					}
				}
				else
				{
					strHex = _T("?? ?? ?? ?? ?? ?? ?? ?? - ?? ?? ?? ?? ?? ?? ?? ??");
				}
				_tcsncpy_s(pItem->pszText, pItem->cchTextMax, strHex, _TRUNCATE);
			}
			else if (pItem->iSubItem == 2)
			{
				CString strAscii;
				if (bRead)
				{
					for (int j = 0; j < 16; j++)
					{
						BYTE b = memData[j];
						if (b >= 32 && b <= 126)
						{
							strAscii += (TCHAR)b;
						}
						else
						{
							strAscii += _T(".");
						}
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

	if (pItem->mask & LVIF_TEXT)
	{
		DWORD rowAddr = m_stackBaseAddr + (pItem->iItem * 4);

		if (pItem->iSubItem == 0)
		{
			CString strAddr;
			strAddr.Format(_T("%08X"), rowAddr);
			_tcsncpy_s(pItem->pszText, pItem->cchTextMax, strAddr, _TRUNCATE);
		}
		else
		{
			DWORD val = 0;
			bool bRead = dbg_ReadMemory(rowAddr, &val, 4);

			if (pItem->iSubItem == 1)
			{
				CString strVal;
				if (bRead)
				{
					strVal.Format(_T("%08X"), val);
				}
				else
				{
					strVal = _T("????????");
				}
				_tcsncpy_s(pItem->pszText, pItem->cchTextMax, strVal, _TRUNCATE);
			}
			else if (pItem->iSubItem == 2)
			{
				CString strComment;
				if (bRead)
				{
					char asciiBuf[5] = { 0 };
					memcpy(asciiBuf, &val, 4);
					for (int j = 0; j < 4; j++)
					{
						if (asciiBuf[j] < 32 || asciiBuf[j] > 126)
						{
							asciiBuf[j] = '.';
						}
					}
					strComment = asciiBuf;
				}
				_tcsncpy_s(pItem->pszText, pItem->cchTextMax, strComment, _TRUNCATE);
			}
		}
	}
	*pResult = 0;
}

void CDebuggerGUIDlg::OnGetdispinfoListBPs(NMHDR* pNMHDR, LRESULT* pResult)
{
	NMLVDISPINFO* pDispInfo = reinterpret_cast<NMLVDISPINFO*>(pNMHDR);
	LVITEM* pItem = &(pDispInfo->item);

	if (pItem->mask & LVIF_TEXT)
	{
		BPDisplayInfo info;
		if (dbg_GetBPInfo(pItem->iItem, &info))
		{
			if (pItem->iSubItem == 0)
			{
				if (info.type == 0)
					_tcsncpy_s(pItem->pszText, pItem->cchTextMax, _T("软件断点"), _TRUNCATE);
				else if (info.type == 1)
					_tcsncpy_s(pItem->pszText, pItem->cchTextMax, _T("硬件执行"), _TRUNCATE);
				else if (info.type == 2)
					_tcsncpy_s(pItem->pszText, pItem->cchTextMax, _T("硬件写入"), _TRUNCATE);
				else
					_tcsncpy_s(pItem->pszText, pItem->cchTextMax, _T("硬件访问"), _TRUNCATE);
			}
			else if (pItem->iSubItem == 1)
			{
				CString str;
				str.Format(_T("%08X"), info.address);
				_tcsncpy_s(pItem->pszText, pItem->cchTextMax, str, _TRUNCATE);
			}
			else if (pItem->iSubItem == 2)
			{
				_tcsncpy_s(pItem->pszText, pItem->cchTextMax, _T("PE Image"), _TRUNCATE);
			}
			else if (pItem->iSubItem == 3)
			{
				if (info.active)
				{
					_tcsncpy_s(pItem->pszText, pItem->cchTextMax, _T("已启用"), _TRUNCATE);
				}
				else
				{
					_tcsncpy_s(pItem->pszText, pItem->cchTextMax, _T("已禁用"), _TRUNCATE);
				}
			}
		}
	}
	*pResult = 0;
}

void CDebuggerGUIDlg::OnGetdispinfoListMMap(NMHDR* pNMHDR, LRESULT* pResult)
{
	NMLVDISPINFO* pDispInfo = reinterpret_cast<NMLVDISPINFO*>(pNMHDR);
	LVITEM* pItem = &(pDispInfo->item);

	if (pItem->mask & LVIF_TEXT)
	{
		MemMapItem item;
		if (dbg_GetMemoryMapItem(pItem->iItem, &item))
		{
			if (pItem->iSubItem == 0)
			{
				CString str;
				str.Format(_T("%08X"), item.address);
				_tcsncpy_s(pItem->pszText, pItem->cchTextMax, str, _TRUNCATE);
			}
			else if (pItem->iSubItem == 1)
			{
				CString str;
				str.Format(_T("%08X"), item.size);
				_tcsncpy_s(pItem->pszText, pItem->cchTextMax, str, _TRUNCATE);
			}
			else if (pItem->iSubItem == 2)
			{
				CString str(item.info);
				_tcsncpy_s(pItem->pszText, pItem->cchTextMax, str, _TRUNCATE);
			}
			else if (pItem->iSubItem == 3)
			{
				CString str(item.protection);
				_tcsncpy_s(pItem->pszText, pItem->cchTextMax, str, _TRUNCATE);
			}
			else if (pItem->iSubItem == 4)
			{
				CString str(item.initProtect);
				_tcsncpy_s(pItem->pszText, pItem->cchTextMax, str, _TRUNCATE);
			}
		}
	}
	*pResult = 0;
}

void CDebuggerGUIDlg::OnGetdispinfoListCStack(NMHDR* pNMHDR, LRESULT* pResult)
{
	NMLVDISPINFO* pDispInfo = reinterpret_cast<NMLVDISPINFO*>(pNMHDR);
	LVITEM* pItem = &(pDispInfo->item);

	if (pItem->mask & LVIF_TEXT)
	{
		CallStackItem item;
		if (dbg_GetCallStackItem(pItem->iItem, &item))
		{
			if (pItem->iSubItem == 0)
			{
				CString str;
				str.Format(_T("%08X"), item.ebp);
				_tcsncpy_s(pItem->pszText, pItem->cchTextMax, str, _TRUNCATE);
			}
			else if (pItem->iSubItem == 1)
			{
				CString str;
				str.Format(_T("%08X"), item.retTo);
				_tcsncpy_s(pItem->pszText, pItem->cchTextMax, str, _TRUNCATE);
			}
			else if (pItem->iSubItem == 2)
			{
				CString str(item.moduleName);
				_tcsncpy_s(pItem->pszText, pItem->cchTextMax, str, _TRUNCATE);
			}
		}
	}
	*pResult = 0;
}

// ==== 反汇编右键菜单处理 ====
void CDebuggerGUIDlg::OnNMRClickListDisasm(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	*pResult = 0;

	int row = pNMItemActivate->iItem;
	if (row < 0)
	{
		return;
	}

	CListCtrl* pList = (CListCtrl*)GetDlgItem(IDC_LIST_DISASM);
	pList->SetItemState(row, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);

	InstrInfo info;
	if (!dbg_GetGlobalDisasmItem(row, &info))
	{
		return;
	}

	CMenu menu;
	menu.CreatePopupMenu();

	if (dbg_HasBreakpoint(info.address))
	{
		menu.AppendMenu(MF_STRING, 1001, _T("取消 软件断点 (F2)"));
	}
	else
	{
		menu.AppendMenu(MF_STRING, 1001, _T("设置 软件断点 (F2)"));
	}

	menu.AppendMenu(MF_SEPARATOR);

	if (dbg_HasHardwareBreakpoint(info.address))
	{
		menu.AppendMenu(MF_STRING, 1003, _T("取消 硬件执行断点"));
	}
	else
	{
		menu.AppendMenu(MF_STRING, 1002, _T("设置 硬件执行断点 (DRx)"));
	}

	CPoint point;
	GetCursorPos(&point);

	int cmd = menu.TrackPopupMenu(TPM_RETURNCMD | TPM_LEFTALIGN | TPM_RIGHTBUTTON, point.x, point.y, this);

	if (cmd == 1001)
	{
		if (dbg_HasBreakpoint(info.address))
		{
			dbg_RemoveBreakpoint(info.address);
		}
		else
		{
			dbg_SetBreakpoint(info.address);
		}
	}
	else if (cmd == 1002)
	{
		dbg_SetHardwareBreakpoint(info.address, 0, 1);
	}
	else if (cmd == 1003)
	{
		dbg_RemoveHardwareBreakpoint(info.address);
	}

	pList->Invalidate();
	RefreshBreakpointsTab();
}

void CDebuggerGUIDlg::OnCustomDrawListDisasm(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMLVCUSTOMDRAW pLVCD = reinterpret_cast<LPNMLVCUSTOMDRAW>(pNMHDR);
	*pResult = CDRF_DODEFAULT;

	if (pLVCD->nmcd.dwDrawStage == CDDS_PREPAINT)
	{
		*pResult = CDRF_NOTIFYITEMDRAW;
	}
	else if (pLVCD->nmcd.dwDrawStage == CDDS_ITEMPREPAINT)
	{
		pLVCD->nmcd.uItemState &= ~CDIS_SELECTED;
		*pResult = CDRF_NOTIFYSUBITEMDRAW;
	}
	else if (pLVCD->nmcd.dwDrawStage == (CDDS_ITEMPREPAINT | CDDS_SUBITEM))
	{
		COLORREF textColor = RGB(0, 0, 0);
		COLORREF bgColor = RGB(255, 255, 255);
		int rowIndex = (int)pLVCD->nmcd.dwItemSpec;
		InstrInfo info;

		if (dbg_GetGlobalDisasmItem(rowIndex, &info))
		{
			CListCtrl* pList = (CListCtrl*)GetDlgItem(IDC_LIST_DISASM);

			if (pList->GetItemState(rowIndex, LVIS_SELECTED) == LVIS_SELECTED)
			{
				bgColor = RGB(225, 225, 225);
			}

			if (pLVCD->iSubItem == 0)
			{
				if (info.address == m_currentEIP)
				{
					bgColor = RGB(164, 250, 120);
					textColor = RGB(0, 0, 0);
				}
				else if (dbg_HasBreakpoint(info.address))
				{
					bgColor = RGB(250, 100, 100);
					textColor = RGB(255, 255, 255);
				}
				else if (dbg_HasHardwareBreakpoint(info.address))
				{
					bgColor = RGB(100, 180, 250);
					textColor = RGB(255, 255, 255);
				}
			}

			if (pLVCD->iSubItem == 2)
			{
				CString asmStr(info.assembly);
				asmStr.MakeUpper();

				if (asmStr.Find(_T("CALL")) == 0)
				{
					textColor = RGB(0, 0, 200);
				}
				else if (asmStr.Find(_T("JMP")) == 0 || asmStr.Find(_T("J")) == 0)
				{
					textColor = RGB(200, 0, 0);
				}
				else if (asmStr.Find(_T("PUSH")) == 0 || asmStr.Find(_T("POP")) == 0 || asmStr.Find(_T("RET")) == 0)
				{
					textColor = RGB(150, 0, 150);
				}
				else if (asmStr.Find(_T("XOR")) == 0 || asmStr.Find(_T("SUB")) == 0 || asmStr.Find(_T("ADD")) == 0 || asmStr.Find(_T("INC")) == 0)
				{
					textColor = RGB(0, 128, 0);
				}
				else if (asmStr.Find(_T("INT3")) != -1 || asmStr.Find(_T("NOP")) != -1)
				{
					textColor = RGB(128, 128, 128);
				}
			}
		}

		pLVCD->clrText = textColor;
		pLVCD->clrTextBk = bgColor;
		*pResult = CDRF_NEWFONT;
	}
}

void CDebuggerGUIDlg::OnNMDblclkListRegs(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	*pResult = 0;

	int row = pNMItemActivate->iItem;
	if (row < 0 || m_currentThreadId == 0)
	{
		return;
	}

	CListCtrl* pList = (CListCtrl*)GetDlgItem(IDC_LIST_REGS);
	CString regName = pList->GetItemText(row, 0);
	CString regVal = pList->GetItemText(row, 1);

	CEditRegDlg dlg;
	dlg.m_strRegName = regName;
	dlg.m_strRegValue = regVal;

	if (dlg.DoModal() == IDOK)
	{
		DWORD newVal = _tcstoul(dlg.m_strRegValue, nullptr, 16);
		char ansiName[16] = { 0 };
		WideCharToMultiByte(CP_ACP, 0, regName, -1, ansiName, 16, NULL, NULL);

		if (dbg_SetRegister(m_currentThreadId, ansiName, newVal))
		{
			CString newStr;
			newStr.Format(_T("%08X"), newVal);
			pList->SetItemText(row, 1, newStr);

			if (regName == _T("EIP"))
			{
				dbg_EnsureDisasm(newVal);
				CListCtrl* pDisasm = (CListCtrl*)GetDlgItem(IDC_LIST_DISASM);
				pDisasm->SetItemCountEx(dbg_GetGlobalDisasmCount(), LVSICF_NOSCROLL);

				int newIndex = dbg_FindDisasmIndexByAddr(newVal);
				if (newIndex != -1)
				{
					POSITION pos = pDisasm->GetFirstSelectedItemPosition();
					while (pos)
					{
						int nItem = pDisasm->GetNextSelectedItem(pos);
						pDisasm->SetItemState(nItem, 0, LVIS_SELECTED | LVIS_FOCUSED);
					}

					pDisasm->SetItemState(newIndex, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
					pDisasm->EnsureVisible(newIndex, FALSE);
				}

				pDisasm->Invalidate();
				pDisasm->SetFocus();
			}
		}
	}
}

BOOL CDebuggerGUIDlg::PreTranslateMessage(MSG* pMsg)
{
	if (pMsg->message == WM_KEYDOWN || pMsg->message == WM_SYSKEYDOWN)
	{
		if (pMsg->wParam == VK_RETURN)
		{
			CWnd* pFocus = GetFocus();
			if (pFocus && pFocus->GetDlgCtrlID() == IDC_EDIT_COMMAND)
			{
				CString strCmd;
				pFocus->GetWindowText(strCmd);
				ProcessCommand(strCmd);
				pFocus->SetWindowText(_T(""));
				return TRUE;
			}
		}

		BOOL bCtrl = (GetKeyState(VK_CONTROL) & 0x8000) != 0;
		BOOL bAlt = (pMsg->message == WM_SYSKEYDOWN);

		if (pMsg->wParam == VK_F9 && !bCtrl && !bAlt) { OnDbgRun(); return TRUE; }
		if (pMsg->wParam == VK_F4 && !bCtrl && !bAlt) { OnDbgRunToCursor(); return TRUE; }
		if (pMsg->wParam == VK_F12 && !bCtrl && !bAlt) { OnDbgPause(); return TRUE; }
		if (pMsg->wParam == VK_F2 && bCtrl && !bAlt) { OnDbgRestart(); return TRUE; }
		if (pMsg->wParam == VK_F2 && !bCtrl && bAlt) { OnDbgStop(); return TRUE; }
		if (pMsg->wParam == VK_F7 && !bCtrl && !bAlt) { OnDbgStepIn(); return TRUE; }
		if (pMsg->wParam == VK_F8 && !bCtrl && !bAlt) { OnDbgStepOver(); return TRUE; }
		if (pMsg->wParam == VK_F9 && bCtrl && !bAlt) { OnDbgRunToReturn(); return TRUE; }
		if (pMsg->wParam == VK_F9 && !bCtrl && bAlt) { OnDbgRunToUserCode(); return TRUE; }

		if (pMsg->wParam == VK_F2 && !bCtrl && !bAlt)
		{
			CWnd* pList = GetDlgItem(IDC_LIST_DISASM);

			if (pList && GetFocus() == pList && m_tabMain.GetCurSel() == TAB_CPU)
			{
				CListCtrl* pListCtrl = (CListCtrl*)pList;
				POSITION pos = pListCtrl->GetFirstSelectedItemPosition();

				if (pos)
				{
					int nItem = pListCtrl->GetNextSelectedItem(pos);
					InstrInfo info;

					if (dbg_GetGlobalDisasmItem(nItem, &info))
					{
						if (dbg_HasBreakpoint(info.address))
						{
							dbg_RemoveBreakpoint(info.address);
						}
						else
						{
							dbg_SetBreakpoint(info.address);
						}
						pListCtrl->Invalidate();
						RefreshBreakpointsTab();
					}
				}
				return TRUE;
			}
		}
	}
	return CDialogEx::PreTranslateMessage(pMsg);
}

void CDebuggerGUIDlg::ProcessCommand(const CString& cmd)
{
	CString str = cmd;
	str.Trim();

	if (str.IsEmpty())
	{
		return;
	}

	CString strLower = str;
	strLower.MakeLower();

	if (strLower.Left(3) == _T("bp "))
	{
		CString strArg = str.Mid(3);
		strArg.Trim();

		DWORD addr = 0;

		// 1. 判断输入的是不是纯十六进制数字
		bool isHex = true;
		for (int i = 0; i < strArg.GetLength(); i++)
		{
			TCHAR c = strArg.GetAt(i);
			if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == 'x' || c == 'X'))
			{
				isHex = false;
				break;
			}
		}

		if (isHex)
		{
			// 如果是数字，直接转换为地址
			addr = _tcstoul(strArg, nullptr, 16);
		}
		else
		{
			// 如果不是数字，说明用户输入了 API 函数名 (如 MessageBox)
			// 将宽字符转换为 ANSI 字符串
			char ansiApiName[128] = { 0 };
			WideCharToMultiByte(CP_ACP, 0, strArg, -1, ansiApiName, 128, NULL, NULL);

			// 调用引擎解析绝对地址
			addr = dbg_ResolveApiAddress(ansiApiName);

			if (addr == 0)
			{
				CString msg;
				msg.Format(_T("无法在系统核心模块中找到函数: %s"), strArg);
				AfxMessageBox(msg);
				return;
			}
			else
			{
				// 解析成功，给出贴心提示
				CString msg;
				msg.Format(_T("成功解析 API [%s] 的系统地址: 0x%08X"), strArg, addr);
				// 此处如果不希望弹窗提示，可以将下面这行注释掉
				AfxMessageBox(msg);
			}
		}

		if (addr != 0)
		{
			dbg_SetBreakpoint(addr);
		}
	}
	else if (strLower.Left(4) == _T("bph "))
	{
		CString strAddr = str.Mid(4);
		strAddr.Trim();

		DWORD addr = _tcstoul(strAddr, nullptr, 16);

		if (addr != 0)
		{
			dbg_SetHardwareBreakpoint(addr, 0, 1);
		}
	}
	else if (strLower.Left(5) == _T("bphc "))
	{
		CString strAddr = str.Mid(5);
		strAddr.Trim();

		DWORD addr = _tcstoul(strAddr, nullptr, 16);

		if (addr != 0)
		{
			dbg_RemoveHardwareBreakpoint(addr);
		}
	}

	CWnd* pDisasm = GetDlgItem(IDC_LIST_DISASM);
	if (pDisasm)
	{
		pDisasm->Invalidate();
	}
	RefreshBreakpointsTab();
}

void CDebuggerGUIDlg::OnSize(UINT nType, int cx, int cy)
{
	CDialogEx::OnSize(nType, cx, cy);

	if (cx <= 0 || cy <= 0) return;

	CWnd* pDisasm = GetDlgItem(IDC_LIST_DISASM);
	if (!pDisasm || !pDisasm->GetSafeHwnd()) return;

	if (m_nSplitterX == 0) m_nSplitterX = cx - 350;
	if (m_nSplitterY == 0) m_nSplitterY = (cy) * 2 / 3;

	if (m_nSplitterX < 150) m_nSplitterX = 150;
	if (m_nSplitterX > cx - 150) m_nSplitterX = cx - 150;
	if (m_nSplitterY < 100) m_nSplitterY = 100;
	if (m_nSplitterY > cy - 100) m_nSplitterY = cy - 100;

	int sp = 3;
	int cmdHeight = 25;

	if (m_tabMain.GetSafeHwnd())
	{
		m_tabMain.MoveWindow(5, 5, m_nSplitterX - 5 - sp, m_nSplitterY - 5 - sp);
	}

	CRect rectTab;
	if (m_tabMain.GetSafeHwnd())
	{
		m_tabMain.GetWindowRect(&rectTab);
		ScreenToClient(&rectTab);
		m_tabMain.AdjustRect(FALSE, &rectTab);
	}
	else
	{
		rectTab.SetRect(5, 5, m_nSplitterX - 5 - sp, m_nSplitterY - 5 - sp);
	}

	pDisasm->MoveWindow(rectTab);

	if (m_listBreakpoints.GetSafeHwnd())
	{
		m_listBreakpoints.MoveWindow(rectTab);
	}
	if (m_listMemMap.GetSafeHwnd())
	{
		m_listMemMap.MoveWindow(rectTab);
	}
	if (m_listCallStack.GetSafeHwnd())
	{
		m_listCallStack.MoveWindow(rectTab);
	}

	CWnd* pMemory = GetDlgItem(IDC_LIST_MEMORY);
	if (pMemory)
	{
		pMemory->MoveWindow(5, m_nSplitterY + sp, m_nSplitterX - 5 - sp, cy - m_nSplitterY - sp - 5 - cmdHeight);
	}

	CWnd* pRegs = GetDlgItem(IDC_LIST_REGS);
	if (pRegs)
	{
		pRegs->MoveWindow(m_nSplitterX + sp, 5, cx - m_nSplitterX - sp - 5, m_nSplitterY - 5 - sp);
	}

	CWnd* pStack = GetDlgItem(IDC_LIST_STACK);
	if (pStack)
	{
		pStack->MoveWindow(m_nSplitterX + sp, m_nSplitterY + sp, cx - m_nSplitterX - sp - 5, cy - m_nSplitterY - sp - 5 - cmdHeight);
	}

	CWnd* pCmdText = GetDlgItem(IDC_STATIC);
	CWnd* pCmdEdit = GetDlgItem(IDC_EDIT_COMMAND);

	if (pCmdEdit)
	{
		if (pCmdText)
		{
			pCmdText->MoveWindow(10, cy - cmdHeight, 35, cmdHeight - 5);
		}
		pCmdEdit->MoveWindow(45, cy - cmdHeight, cx - 55, cmdHeight - 5);
	}
}

void CDebuggerGUIDlg::OnLButtonDown(UINT nFlags, CPoint point)
{
	CRect rectClient;
	GetClientRect(&rectClient);

	int sp = 4;
	CRect rectSplitterX(m_nSplitterX - sp, 5, m_nSplitterX + sp, rectClient.bottom);
	CRect rectSplitterY(0, m_nSplitterY - sp, rectClient.right, m_nSplitterY + sp);

	bool bHitX = rectSplitterX.PtInRect(point);
	bool bHitY = rectSplitterY.PtInRect(point);

	if (bHitX || bHitY)
	{
		m_bDraggingX = bHitX;
		m_bDraggingY = bHitY;
		SetCapture();
	}
	CDialogEx::OnLButtonDown(nFlags, point);
}

void CDebuggerGUIDlg::OnLButtonUp(UINT nFlags, CPoint point)
{
	if (m_bDraggingX || m_bDraggingY)
	{
		m_bDraggingX = false;
		m_bDraggingY = false;
		ReleaseCapture();
	}
	CDialogEx::OnLButtonUp(nFlags, point);
}

void CDebuggerGUIDlg::OnMouseMove(UINT nFlags, CPoint point)
{
	if (m_bDraggingX || m_bDraggingY)
	{
		if (m_bDraggingX) m_nSplitterX = point.x;
		if (m_bDraggingY) m_nSplitterY = point.y;

		CRect rect;
		GetClientRect(&rect);
		OnSize(0, rect.Width(), rect.Height());
	}
	CDialogEx::OnMouseMove(nFlags, point);
}

BOOL CDebuggerGUIDlg::OnSetCursor(CWnd* pWnd, UINT nHitTest, UINT message)
{
	if (pWnd == this)
	{
		CPoint point;
		GetCursorPos(&point);
		ScreenToClient(&point);

		CRect rectClient;
		GetClientRect(&rectClient);

		int sp = 4;
		CRect rectSplitterX(m_nSplitterX - sp, 5, m_nSplitterX + sp, rectClient.bottom);
		CRect rectSplitterY(0, m_nSplitterY - sp, rectClient.right, m_nSplitterY + sp);

		bool bHitX = rectSplitterX.PtInRect(point);
		bool bHitY = rectSplitterY.PtInRect(point);

		if (bHitX && bHitY)
		{
			SetCursor(AfxGetApp()->LoadStandardCursor(IDC_SIZEALL));
			return TRUE;
		}
		else if (bHitX)
		{
			SetCursor(AfxGetApp()->LoadStandardCursor(IDC_SIZEWE));
			return TRUE;
		}
		else if (bHitY)
		{
			SetCursor(AfxGetApp()->LoadStandardCursor(IDC_SIZENS));
			return TRUE;
		}
	}
	return CDialogEx::OnSetCursor(pWnd, nHitTest, message);
}