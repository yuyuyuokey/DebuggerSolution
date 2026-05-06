#pragma once
#include <vector>
#include "afxdialogex.h"
#include "resource.h"

struct SmartBPItem
{
    DWORD address;
    CString type;
    CString description;
    CString reason;
    bool selected;
};

class CAIBreakpointRecommendDlg : public CDialogEx
{
public:
    CAIBreakpointRecommendDlg(CWnd* pParent = nullptr);

    std::vector<SmartBPItem> m_items;

#ifdef AFX_DESIGN_TIME
    enum { IDD = IDD_DLG_SMART_BP };
#endif

protected:
    virtual void DoDataExchange(CDataExchange* pDX);
    virtual BOOL OnInitDialog();

    afx_msg void OnBnClickedSelectAll();
    afx_msg void OnBnClickedApplyBp();

    DECLARE_MESSAGE_MAP()

private:
    CListCtrl m_list;
    void RefreshList();
};
