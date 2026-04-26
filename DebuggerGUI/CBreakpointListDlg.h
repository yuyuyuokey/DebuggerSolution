#pragma once
#include "afxdialogex.h"
#include "resource.h"

class CBreakpointListDlg : public CDialogEx
{
public:
	CBreakpointListDlg(CWnd* pParent = nullptr);

	// 由于这个在UI建立期间让你添加后漏接了对话图纸，这里干脆绕过需要关联强配UI画设：使用你此前早已备用的编辑窗口( IDD_DLG_EDIT_REG 借道做背景体) 
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DLG_EDIT_REG };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);

protected:
	virtual BOOL OnInitDialog();
	afx_msg void OnBnClickedBtnDelBp();

	DECLARE_MESSAGE_MAP()
private:
	void RefreshBreakpoints();
};