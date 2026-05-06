#include "pch.h"
#include "CAIBreakpointRecommendDlg.h"
#include "DebuggerAPI.h"

CAIBreakpointRecommendDlg::CAIBreakpointRecommendDlg(CWnd* pParent)
    : CDialogEx(IDD_DLG_SMART_BP, pParent)
{
}

void CAIBreakpointRecommendDlg::DoDataExchange(CDataExchange* pDX)
{
    CDialogEx::DoDataExchange(pDX);
    DDX_Control(pDX, IDC_LIST_SMART_BP, m_list);
}

BEGIN_MESSAGE_MAP(CAIBreakpointRecommendDlg, CDialogEx)
    ON_BN_CLICKED(IDC_BTN_SELECTALL, &CAIBreakpointRecommendDlg::OnBnClickedSelectAll)
    ON_BN_CLICKED(IDC_BTN_APPLYBP, &CAIBreakpointRecommendDlg::OnBnClickedApplyBp)
END_MESSAGE_MAP()

BOOL CAIBreakpointRecommendDlg::OnInitDialog()
{
    CDialogEx::OnInitDialog();
    SetWindowText(_T("AI Smart Breakpoint Recommendations"));

    m_list.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_CHECKBOXES);
    m_list.InsertColumn(0, _T("Address"), LVCFMT_LEFT, 90);
    m_list.InsertColumn(1, _T("Type"), LVCFMT_LEFT, 100);
    m_list.InsertColumn(2, _T("Description"), LVCFMT_LEFT, 180);
    m_list.InsertColumn(3, _T("Reason"), LVCFMT_LEFT, 200);

    RefreshList();
    return TRUE;
}

void CAIBreakpointRecommendDlg::RefreshList()
{
    m_list.DeleteAllItems();

    for (int i = 0; i < (int)m_items.size(); i++)
    {
        CString strAddr;
        strAddr.Format(_T("0x%08X"), m_items[i].address);
        m_list.InsertItem(i, strAddr);
        m_list.SetItemText(i, 1, m_items[i].type);
        m_list.SetItemText(i, 2, m_items[i].description);
        m_list.SetItemText(i, 3, m_items[i].reason);

        if (m_items[i].selected)
            m_list.SetCheck(i, TRUE);
    }
}

void CAIBreakpointRecommendDlg::OnBnClickedSelectAll()
{
    bool anyUnchecked = false;
    for (int i = 0; i < (int)m_items.size(); i++)
    {
        if (!m_list.GetCheck(i))
        {
            anyUnchecked = true;
            break;
        }
    }

    for (int i = 0; i < (int)m_items.size(); i++)
    {
        m_list.SetCheck(i, anyUnchecked);
        m_items[i].selected = anyUnchecked;
    }
}

void CAIBreakpointRecommendDlg::OnBnClickedApplyBp()
{
    int applied = 0;
    for (int i = 0; i < (int)m_items.size(); i++)
    {
        BOOL checked = m_list.GetCheck(i);
        m_items[i].selected = (checked == TRUE);

        if (m_items[i].selected && m_items[i].address != 0)
        {
            if (!dbg_HasBreakpoint(m_items[i].address))
            {
                dbg_SetBreakpoint(m_items[i].address);
                applied++;
            }
        }
    }

    CString msg;
    msg.Format(_T("Applied %d breakpoint(s)."), applied);
    AfxMessageBox(msg);

    CDialogEx::OnOK();
}
