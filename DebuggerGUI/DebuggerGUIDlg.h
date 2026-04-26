#pragma once
#define WM_DEBUG_EVENT (WM_USER + 100)

#include "resource.h"

// CDebuggerGUIDlg 对话框
class CDebuggerGUIDlg : public CDialogEx
{
public:
	CDebuggerGUIDlg(CWnd* pParent = nullptr);

	afx_msg LRESULT OnDebugEvent(WPARAM wParam, LPARAM lParam);

	DWORD m_currentThreadId = 0;
	DWORD m_currentEIP = 0;
	DWORD m_currentDumpAddr = 0x00400000;

	// 滑动窗口的内存基址
	DWORD m_stackBaseAddr = 0;
	DWORD m_memoryBaseAddr = 0;

	// ==========================================
	// 【新增】：十字动态分割条的底层变量
	// ==========================================
	int m_nSplitterX = 0;      // 竖向分割线的 X 坐标
	int m_nSplitterY = 0;      // 横向分割线的 Y 坐标
	bool m_bDraggingX = false; // 是否正在拖拽左右
	bool m_bDraggingY = false; // 是否正在拖拽上下

#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DEBUGGERGUI_DIALOG };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);

protected:
	HICON m_hIcon;

	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();

	DECLARE_MESSAGE_MAP()

public:
	afx_msg void OnBnClickedBtnStart();
	afx_msg void OnBnClickedBtnStepIn();
	afx_msg void OnBnClickedBtnRun();
	afx_msg void OnBnClickedBtnStepOver();
	afx_msg void OnBnClickedBtnSetBp();

	afx_msg void OnGetdispinfoListDisasm(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnNMDblclkListRegs(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnSize(UINT nType, int cx, int cy);
	afx_msg void OnClose();

	afx_msg void OnGetdispinfoListMemory(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnGetdispinfoListStack(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnCustomDrawListDisasm(NMHDR* pNMHDR, LRESULT* pResult);

	// ==========================================
	// 【新增】：捕获鼠标消息，实现 OD 级自由拉伸！
	// ==========================================
	afx_msg void OnLButtonDown(UINT nFlags, CPoint point);
	afx_msg void OnLButtonUp(UINT nFlags, CPoint point);
	afx_msg void OnMouseMove(UINT nFlags, CPoint point);
	afx_msg BOOL OnSetCursor(CWnd* pWnd, UINT nHitTest, UINT message);

	virtual BOOL PreTranslateMessage(MSG* pMsg);
};