#pragma once
#include "afxdialogex.h"
#include "resource.h"

class CAIFunctionListDlg : public CDialogEx
{
public:
	CAIFunctionListDlg(CWnd* pParent = nullptr);

	DWORD m_selectedAddress;

#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DLG_AI_FUNC_LIST };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);
	virtual BOOL OnInitDialog();

	afx_msg void OnBnClickedJump();
	afx_msg void OnBnClickedRefresh();
	afx_msg void OnNMDblclkListFunctions(NMHDR* pNMHDR, LRESULT* pResult);

	DECLARE_MESSAGE_MAP()

private:
	void RefreshFunctionList();

	CListCtrl m_list;
};
