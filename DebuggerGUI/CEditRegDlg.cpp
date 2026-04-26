#include "pch.h"
#include "DebuggerGUI.h"
#include "CEditRegDlg.h"

CEditRegDlg::CEditRegDlg(CWnd* pParent) : CDialogEx(IDD_DLG_EDIT_REG, pParent) {}

void CEditRegDlg::DoDataExchange(CDataExchange* pDX) { CDialogEx::DoDataExchange(pDX); }
BEGIN_MESSAGE_MAP(CEditRegDlg, CDialogEx)
	ON_BN_CLICKED(IDOK, &CEditRegDlg::OnBnClickedOk)
END_MESSAGE_MAP()

BOOL CEditRegDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();
	// 把标题改成“修改 EAX”等
	CString title; title.Format(_T("修改寄存器: %s"), m_strRegName);
	SetWindowText(title);
	// 把原来的值填进输入框
	SetDlgItemText(IDC_EDIT_REG_VAL, m_strRegValue);
	return TRUE;
}

void CEditRegDlg::OnBnClickedOk()
{
	// 点击确定时，把新输入的值保存下来
	GetDlgItemText(IDC_EDIT_REG_VAL, m_strRegValue);
	CDialogEx::OnOK();
}