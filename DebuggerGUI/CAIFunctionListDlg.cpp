#include "pch.h"
#include "CAIFunctionListDlg.h"
#include "DebuggerAPI.h"

CAIFunctionListDlg::CAIFunctionListDlg(CWnd* pParent)
	: CDialogEx(IDD_DLG_AI_FUNC_LIST, pParent)
	, m_selectedAddress(0)
{
}

void CAIFunctionListDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_AI_FUNCS, m_list);
}

BEGIN_MESSAGE_MAP(CAIFunctionListDlg, CDialogEx)
	ON_BN_CLICKED(IDC_BTN_FUNC_JUMP, &CAIFunctionListDlg::OnBnClickedJump)
	ON_BN_CLICKED(IDC_BTN_FUNC_REFRESH, &CAIFunctionListDlg::OnBnClickedRefresh)
	ON_NOTIFY(NM_DBLCLK, IDC_LIST_AI_FUNCS, &CAIFunctionListDlg::OnNMDblclkListFunctions)
END_MESSAGE_MAP()

BOOL CAIFunctionListDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	SetWindowText(_T("AI Function List"));
	m_list.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	m_list.InsertColumn(0, _T("Start"), LVCFMT_LEFT, 100);
	m_list.InsertColumn(1, _T("End"), LVCFMT_LEFT, 100);
	m_list.InsertColumn(2, _T("Name"), LVCFMT_LEFT, 160);
	m_list.InsertColumn(3, _T("Signature"), LVCFMT_LEFT, 120);
	m_list.InsertColumn(4, _T("Feature"), LVCFMT_LEFT, 140);

	RefreshFunctionList();
	return TRUE;
}

void CAIFunctionListDlg::RefreshFunctionList()
{
	m_list.DeleteAllItems();

	const int count = dbg_GetFunctionAnalysisCount();
	for (int i = 0; i < count; ++i)
	{
		FunctionAnalysisInfo info = { 0 };
		if (!dbg_GetFunctionAnalysisItem(i, &info))
		{
			continue;
		}

		CString startStr;
		CString endStr;
		startStr.Format(_T("%08X"), info.startAddr);
		endStr.Format(_T("%08X"), info.endAddr);

		const int row = m_list.InsertItem(i, startStr);
		m_list.SetItemText(row, 1, endStr);
		m_list.SetItemText(row, 2, CString(info.name));
		m_list.SetItemText(row, 3, CString(info.signature));
		m_list.SetItemText(row, 4, CString(info.feature));
		m_list.SetItemData(row, info.startAddr);
	}
}

void CAIFunctionListDlg::OnBnClickedJump()
{
	const int sel = m_list.GetNextItem(-1, LVNI_SELECTED);
	if (sel < 0)
	{
		return;
	}

	m_selectedAddress = (DWORD)m_list.GetItemData(sel);
	CDialogEx::OnOK();
}

void CAIFunctionListDlg::OnBnClickedRefresh()
{
	dbg_AnalyzeFunctions();
	RefreshFunctionList();
}

void CAIFunctionListDlg::OnNMDblclkListFunctions(NMHDR* pNMHDR, LRESULT* pResult)
{
	UNREFERENCED_PARAMETER(pNMHDR);
	*pResult = 0;
	OnBnClickedJump();
}
