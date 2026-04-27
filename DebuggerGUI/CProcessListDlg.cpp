#include "pch.h"
#include "DebuggerGUI.h"
#include "CProcessListDlg.h"
#include <TlHelp32.h>

CProcessListDlg::CProcessListDlg(CWnd* pParent)
    : CDialogEx(IDD_DLG_PROCLIST, pParent), m_selectedPID(0)
{
}

void CProcessListDlg::DoDataExchange(CDataExchange* pDX)
{
    CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CProcessListDlg, CDialogEx)
    ON_BN_CLICKED(IDOK, &CProcessListDlg::OnBnClickedOk)
    ON_NOTIFY(NM_DBLCLK, IDC_LIST_PROCS, &CProcessListDlg::OnNMDblclkListProcs)
END_MESSAGE_MAP()

BOOL CProcessListDlg::OnInitDialog()
{
    CDialogEx::OnInitDialog();
    SetWindowText(_T("Attach - Choose your process!"));

    CListCtrl* pList = (CListCtrl*)GetDlgItem(IDC_LIST_PROCS);
    if (pList)
    {
        pList->SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
        pList->InsertColumn(0, _T("PID"), LVCFMT_LEFT, 80);
        pList->InsertColumn(1, _T("Target Process"), LVCFMT_LEFT, 260);
    }

    RefreshProcessList();

    return TRUE;
}

void CProcessListDlg::RefreshProcessList()
{
    CListCtrl* pList = (CListCtrl*)GetDlgItem(IDC_LIST_PROCS);
    if (!pList) return;

    pList->DeleteAllItems();

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnap, &pe))
    {
        int i = 0;
        do
        {
            if (pe.th32ProcessID <= 4) continue; // 忽略系统进程

            CString strPid;
            strPid.Format(_T("%u"), pe.th32ProcessID);
            pList->InsertItem(i, strPid);

            CString exeName(pe.szExeFile);
            pList->SetItemText(i, 1, exeName);

            i++;
        } while (Process32Next(hSnap, &pe));
    }

    // 修复：必须关闭句柄，防止句柄泄漏
    CloseHandle(hSnap);
}

void CProcessListDlg::OnBnClickedOk()
{
    CListCtrl* pList = (CListCtrl*)GetDlgItem(IDC_LIST_PROCS);
    if (pList)
    {
        POSITION pos = pList->GetFirstSelectedItemPosition();
        if (pos)
        {
            int nItem = pList->GetNextSelectedItem(pos);
            CString strPid = pList->GetItemText(nItem, 0);
            m_selectedPID = (DWORD)_ttoi(strPid);

            CDialogEx::OnOK();
            return;
        }
    }

    AfxMessageBox(_T("请先在列表中选择一个要附加的进程！"));
}

void CProcessListDlg::OnNMDblclkListProcs(NMHDR* pNMHDR, LRESULT* pResult)
{
    // 双击列表项时直接执行附加确认逻辑
    OnBnClickedOk();
    *pResult = 0;
}