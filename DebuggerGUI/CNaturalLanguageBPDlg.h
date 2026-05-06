#pragma once
#include <vector>
#include <string>
#include "afxdialogex.h"
#include "resource.h"

struct GeneratedBreakpoint
{
    DWORD address;
    CString targetSymbol;
    CString condition;
    CString description;
    CString rawInput;
    bool isValid;
    bool isConditional;
};

class CNaturalLanguageBPDlg : public CDialogEx
{
public:
    CNaturalLanguageBPDlg(CWnd* pParent = nullptr);

    GeneratedBreakpoint m_result;

    enum { IDD = IDD_DLG_NL_BP };

protected:
    virtual void DoDataExchange(CDataExchange* pDX);
    virtual BOOL OnInitDialog();

    afx_msg void OnBnClickedGenerate();
    afx_msg void OnBnClickedSetBreakpoint();

    DECLARE_MESSAGE_MAP()

private:
    CEdit m_editInput;
    CEdit m_editOutput;
    CEdit m_editCondition;
    CStatic m_staticStatus;

    CString BuildNLBPrompt(const CString& userInput);
    bool ParseAIResponse(const std::string& aiResponse, GeneratedBreakpoint* outResult);
    void SetStatus(const CString& text, bool isError = false);
};
