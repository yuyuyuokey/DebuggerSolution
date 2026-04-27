#pragma once
#include "afxdialogex.h"
#include <afxcmn.h> // RichEdit 必须

#define WM_UPDATE_AI_TEXT (WM_USER + 102)


// CAIResultDlg 对话框

class CAIResultDlg : public CDialogEx
{
	DECLARE_DYNAMIC(CAIResultDlg)

public:
	CAIResultDlg(CWnd* pParent = nullptr);   // 标准构造函数
	virtual ~CAIResultDlg();

	CString m_strAsmCode;    // 传入的待分析汇编代码
	CString m_strFinalResult; // AI 返回的结果
	CRichEditCtrl m_richEdit; // 关联控件
	CFont m_fontTitle;
	CFont m_fontContent;

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG_AI_RESULT };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持
	virtual BOOL OnInitDialog();
	afx_msg LRESULT OnUpdateText(WPARAM wParam, LPARAM lParam); // 异步更新消息


	DECLARE_MESSAGE_MAP()

	// 内部线程函数
	static UINT __cdecl AIWorkerThread(LPVOID pParam);
};