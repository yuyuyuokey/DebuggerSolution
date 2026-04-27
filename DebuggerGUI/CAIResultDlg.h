#pragma once
#include "afxdialogex.h"
#include <afxcmn.h>

#define WM_UPDATE_AI_TEXT (WM_USER + 102)

class CAIResultDlg : public CDialogEx
{
    DECLARE_DYNAMIC(CAIResultDlg)

public:
    CAIResultDlg(CWnd* pParent = nullptr);
    virtual ~CAIResultDlg();

    CString m_strAsmCode;
    CString m_strFinalResult;
    CRichEditCtrl m_richEdit;
    CFont m_fontTitle;
    CFont m_fontContent;

#ifdef AFX_DESIGN_TIME
    enum { IDD = IDD_DIALOG_AI_RESULT };
#endif

protected:
    virtual void DoDataExchange(CDataExchange* pDX);
    virtual BOOL OnInitDialog();
    afx_msg LRESULT OnUpdateText(WPARAM wParam, LPARAM lParam);

    DECLARE_MESSAGE_MAP()

private:
    static UINT __cdecl AIWorkerThread(LPVOID pParam);
};