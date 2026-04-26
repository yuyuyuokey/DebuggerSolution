#pragma once
#define WM_DEBUG_EVENT (WM_USER + 100)
#include "resource.h"

#define TAB_CPU 0
#define TAB_BREAKPOINTS 1
#define TAB_MEMMAP 2
#define TAB_CALLSTACK 3

#define IDC_LIST_BPS 2001
#define IDC_LIST_MMAP 2002
#define IDC_LIST_CSTACK 2003

class CDebuggerGUIDlg : public CDialogEx
{
public:
	CDebuggerGUIDlg(CWnd* pParent = nullptr);

	afx_msg LRESULT OnDebugEvent(WPARAM wParam, LPARAM lParam);

	DWORD m_currentThreadId = 0;
	DWORD m_currentEIP = 0;
	DWORD m_currentDumpAddr = 0x00400000;
	DWORD m_stackBaseAddr = 0;
	DWORD m_memoryBaseAddr = 0;

	int m_nSplitterX = 0;
	int m_nSplitterY = 0;
	bool m_bDraggingX = false;
	bool m_bDraggingY = false;

#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DEBUGGERGUI_DIALOG };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);

protected:
	HICON m_hIcon;

	CTabCtrl m_tabMain;
	CListCtrl m_listBreakpoints;
	CListCtrl m_listMemMap;
	CListCtrl m_listCallStack;

	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()

public:
	afx_msg void OnFileOpen();
	afx_msg void OnFileAttach();

	afx_msg void OnViewCpu();
	afx_msg void OnViewBreakpoints();
	afx_msg void OnViewMemmap();
	afx_msg void OnViewCallstack();

	afx_msg void OnDbgRun();
	afx_msg void OnDbgRunToCursor();
	afx_msg void OnDbgPause();
	afx_msg void OnDbgRestart();
	afx_msg void OnDbgStop();
	afx_msg void OnDbgStepIn();
	afx_msg void OnDbgStepOver();
	afx_msg void OnDbgRunToReturn();
	afx_msg void OnDbgRunToUserCode();

	afx_msg void OnGetdispinfoListDisasm(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnGetdispinfoListMemory(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnGetdispinfoListStack(NMHDR* pNMHDR, LRESULT* pResult);

	afx_msg void OnGetdispinfoListBPs(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnGetdispinfoListMMap(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnGetdispinfoListCStack(NMHDR* pNMHDR, LRESULT* pResult);

	afx_msg void OnCustomDrawListDisasm(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnNMDblclkListRegs(NMHDR* pNMHDR, LRESULT* pResult);

	// 【新增】反汇编窗口的右键菜单响应
	afx_msg void OnNMRClickListDisasm(NMHDR* pNMHDR, LRESULT* pResult);

	afx_msg void OnSize(UINT nType, int cx, int cy);
	afx_msg void OnClose();
	afx_msg void OnLButtonDown(UINT nFlags, CPoint point);
	afx_msg void OnLButtonUp(UINT nFlags, CPoint point);
	afx_msg void OnMouseMove(UINT nFlags, CPoint point);
	afx_msg BOOL OnSetCursor(CWnd* pWnd, UINT nHitTest, UINT message);

	afx_msg void OnTcnSelchangeTabMain(NMHDR* pNMHDR, LRESULT* pResult);

	virtual BOOL PreTranslateMessage(MSG* pMsg);

	void ProcessCommand(const CString& cmd);
	void SwitchTab(int tabIndex);
	void RefreshBreakpointsTab();
};