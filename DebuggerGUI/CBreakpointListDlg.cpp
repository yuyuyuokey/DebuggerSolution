#include "pch.h"
#include "DebuggerGUI.h"
#include "CBreakpointListDlg.h"
#include "afxdialogex.h"
#include "DebuggerAPI.h"

CBreakpointListDlg::CBreakpointListDlg(CWnd* pParent) : CDialogEx(IDD_DLG_EDIT_REG, pParent)
{
}

void CBreakpointListDlg::DoDataExchange(CDataExchange* pDX)
{
    CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CBreakpointListDlg, CDialogEx)
    ON_BN_CLICKED(IDOK, &CBreakpointListDlg::OnBnClickedBtnDelBp)
END_MESSAGE_MAP()

BOOL CBreakpointListDlg::OnInitDialog()
{
    CDialogEx::OnInitDialog();

    SetWindowText(_T("BreakPoints Global Center [Readonly-Panel]"));
    GetDlgItem(IDOK)->SetWindowText(_T("Wipe ALL"));

    RefreshBreakpoints();

    return TRUE;
}

void CBreakpointListDlg::RefreshBreakpoints()
{
    int total = dbg_GetTotalBPCount();
    CString strOutput;

    if (total == 0)
    {
        strOutput = _T("  -> Null ... [Nothing In Trap Array!] \r\n");
    }

    for (int i = 0; i < total; i++)
    {
        BPDisplayInfo info;
        if (dbg_GetBPInfo(i, &info))
        {
            CString tempLine;
            tempLine.Format(_T(" BP Id:[%d] => Target ADDR: [ 0x%08X ] Active:%d \r\n"), i, info.address, info.active);
            strOutput += tempLine;
        }
    }

    SetDlgItemText(IDC_EDIT_REG_VAL, strOutput);
}

void CBreakpointListDlg::OnBnClickedBtnDelBp()
{
    int total = dbg_GetTotalBPCount();

    for (int i = total - 1; i >= 0; --i)
    {
        BPDisplayInfo info;
        if (dbg_GetBPInfo(i, &info))
        {
            if (info.type == BP_TYPE_SOFTWARE)
            {
                dbg_RemoveBreakpoint(info.address);
            }
            else
            {
                dbg_RemoveHardwareBreakpoint(info.address);
            }
        }
    }

    RefreshBreakpoints();

    if (GetParent() != NULL)
    {
        GetParent()->Invalidate();
    }
}