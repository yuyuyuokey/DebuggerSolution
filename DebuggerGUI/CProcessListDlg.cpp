#include "pch.h"
#include "DebuggerGUI.h"
#include "CProcessListDlg.h"
#include <TlHelp32.h>

CProcessListDlg::CProcessListDlg(CWnd* pParent) : CDialogEx(IDD_DLG_PROCLIST, pParent), m_selectedPID(0) {}
void CProcessListDlg::DoDataExchange(CDataExchange* pDX) { CDialogEx::DoDataExchange(pDX); }

BEGIN_MESSAGE_MAP(CProcessListDlg, CDialogEx)
	ON_BN_CLICKED(IDOK, &CProcessListDlg::OnBnClickedOk)
	ON_NOTIFY(NM_DBLCLK, IDC_LIST_PROCS, &CProcessListDlg::OnNMDblclkListProcs)
END_MESSAGE_MAP()

BOOL CProcessListDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();
	SetWindowText(_T("Attach - Choose your process!"));

	CListCtrl* pList = (CListCtrl*)GetDlgItem(IDC_LIST_PROCS);
	if (pList) {
		pList->SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
		pList->InsertColumn(0, _T("PID"), LVCFMT_LEFT, 60);
		pList->InsertColumn(1, _T("Target Process"), LVCFMT_LEFT, 260);
	}
	RefreshProcessList();
	return TRUE;
}

void CProcessListDlg::RefreshProcessList()
{
	CListCtrl* pList = (CListCtrl*)GetDlgItem(IDC_LIST_PROCS);
	pList->DeleteAllItems();
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) return;
	PROCESSENTRY32 pe; pe.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hSnap, &pe)) {
		int i = 0;
		do {
			if (pe.th32ProcessID <= 4) continue;
			CString strPid; strPid.Format(_T("%u"), pe.th32ProcessID);
			pList->InsertItem(i, strPid);
			CString exeName(pe.szExeFile);
			pList->SetItemText(i, 1, exeName);
			i++;
		} while (Process32Next(hSnap, &pe));
	}
	CloseHandle(hSnap);
}

void CProcessListDlg::OnNMDblclkListProcs(NMHDR* pNMHDR, LRESULT* pResult) {
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	*pResult = 0;
	if (pNMItemActivate->iItem >= 0) OnBnClickedOk();
}

void CProcessListDlg::OnBnClickedOk() {
	CListCtrl* pList = (CListCtrl*)GetDlgItem(IDC_LIST_PROCS);
	int sel = pList->GetNextItem(-1, LVNI_SELECTED);
	if (sel != -1) {
		CString strPid = pList->GetItemText(sel, 0);
		m_selectedPID = (DWORD)_ttoi(strPid);
		CDialogEx::OnOK();
	}
}