#pragma once
#include "afxdialogex.h"
#include "resource.h"

class CProcessListDlg : public CDialogEx
{
public:
    CProcessListDlg(CWnd* pParent = nullptr);

    // 返回给外部调用的选择结果
    DWORD m_selectedPID;

#ifdef AFX_DESIGN_TIME
    enum { IDD = IDD_DLG_PROCLIST };
#endif

protected:
    virtual void DoDataExchange(CDataExchange* pDX);
    virtual BOOL OnInitDialog();
    afx_msg void OnBnClickedOk();
    afx_msg void OnNMDblclkListProcs(NMHDR* pNMHDR, LRESULT* pResult);

    DECLARE_MESSAGE_MAP()

private:
    // 读取 Windows 快照填充到界面的列表函数
    void RefreshProcessList();
};