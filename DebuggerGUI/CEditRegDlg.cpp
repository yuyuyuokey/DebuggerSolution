#include "pch.h"
#include "DebuggerGUI.h"
#include "CEditRegDlg.h"

CEditRegDlg::CEditRegDlg(CWnd* pParent)
    : CDialogEx(IDD_DLG_EDIT_REG, pParent)
{
}

void CEditRegDlg::DoDataExchange(CDataExchange* pDX)
{
    CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CEditRegDlg, CDialogEx)
    ON_BN_CLICKED(IDOK, &CEditRegDlg::OnBnClickedOk)
END_MESSAGE_MAP()

BOOL CEditRegDlg::OnInitDialog()
{
    CDialogEx::OnInitDialog();

    // 动态修改窗口标题，例如“修改寄存器: EAX”
    CString title;
    title.Format(_T("修改寄存器: %s"), m_strRegName);
    SetWindowText(title);

    // 将原有的寄存器值填入输入框
    SetDlgItemText(IDC_EDIT_REG_VAL, m_strRegValue);

    return TRUE;
}

void CEditRegDlg::OnBnClickedOk()
{
    // 点击确定时，获取新输入的值并保存，供外部调用者读取
    GetDlgItemText(IDC_EDIT_REG_VAL, m_strRegValue);
    CDialogEx::OnOK();
}