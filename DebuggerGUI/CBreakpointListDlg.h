#pragma once
#include "afxdialogex.h"
#include "resource.h"

class CBreakpointListDlg : public CDialogEx
{
public:
    CBreakpointListDlg(CWnd* pParent = nullptr);

#ifdef AFX_DESIGN_TIME
    enum { IDD = IDD_DLG_EDIT_REG };
#endif

protected:
    virtual void DoDataExchange(CDataExchange* pDX);
    virtual BOOL OnInitDialog();
    afx_msg void OnBnClickedBtnDelBp();

    DECLARE_MESSAGE_MAP()

private:
    void RefreshBreakpoints();
};