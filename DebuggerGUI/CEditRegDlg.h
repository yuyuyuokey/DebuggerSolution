#pragma once
#include <afxdialogex.h>
#include "resource.h"

class CEditRegDlg : public CDialogEx
{
public:
    CEditRegDlg(CWnd* pParent = nullptr);

#ifdef AFX_DESIGN_TIME
    enum { IDD = IDD_DLG_EDIT_REG };
#endif

public:
    // 用来和主界面传递数据的变量
    CString m_strRegName;
    CString m_strRegValue;

protected:
    virtual void DoDataExchange(CDataExchange* pDX);
    virtual BOOL OnInitDialog();
    afx_msg void OnBnClickedOk();

    DECLARE_MESSAGE_MAP()
};