#include "pch.h"
#include "DebuggerGUI.h"
#include "afxdialogex.h"
#include "CAIResultDlg.h"
#include "httplib.h"
#include "json.hpp"

extern std::string AskOllamaForHelp(const std::string& prompt_text);

IMPLEMENT_DYNAMIC(CAIResultDlg, CDialogEx)

CAIResultDlg::CAIResultDlg(CWnd* pParent /*=nullptr*/)
    : CDialogEx(IDD_DIALOG_AI_RESULT, pParent)
{
}

CAIResultDlg::~CAIResultDlg()
{
}

void CAIResultDlg::DoDataExchange(CDataExchange* pDX)
{
    CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAIResultDlg, CDialogEx)
    ON_MESSAGE(WM_UPDATE_AI_TEXT, &CAIResultDlg::OnUpdateText)
END_MESSAGE_MAP()

// 统一合并的辅助函数：向 RichEdit 插入带样式的文字
static void AppendFormattedText(CRichEditCtrl& ctrl, LPCTSTR lpszText, COLORREF color = RGB(0, 0, 0), int nFontSize = 105, bool bBold = false, LPCTSTR lpszFont = _T("微软雅黑"))
{
    CHARFORMAT2 cf;
    ZeroMemory(&cf, sizeof(cf));
    cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_COLOR | CFM_SIZE | CFM_BOLD | CFM_FACE;
    cf.crTextColor = color;
    cf.yHeight = nFontSize * 2; // RichEdit 单位是 1/20 磅
    cf.dwEffects = bBold ? CFE_BOLD : 0;
    _tcscpy_s(cf.szFaceName, lpszFont);

    int nLen = ctrl.GetWindowTextLength();
    ctrl.SetSel(nLen, nLen);
    ctrl.SetSelectionCharFormat(cf);
    ctrl.ReplaceSel(lpszText);
}

BOOL CAIResultDlg::OnInitDialog()
{
    CDialogEx::OnInitDialog();

    m_fontContent.CreatePointFont(105, _T("微软雅黑"));

    CRichEditCtrl* pRich = (CRichEditCtrl*)GetDlgItem(IDC_RICHEDIT_AI);
    if (pRich)
    {
        CRect rect;
        pRich->GetClientRect(&rect);
        rect.DeflateRect(10, 10);
        pRich->SetRect(&rect);

        pRich->SetFont(&m_fontContent);
        pRich->SetBackgroundColor(FALSE, RGB(245, 245, 245));

        CString strInit;
        strInit.Format(_T(" 正在连接 Ollama 模型...\r\n\r\n[目标]:\r\n%s\r\n\r\nAI 正在思考中..."), m_strAsmCode);
        pRich->SetWindowText(strInit);
    }

    AfxBeginThread(AIWorkerThread, this);

    return TRUE;
}

UINT __cdecl CAIResultDlg::AIWorkerThread(LPVOID pParam)
{
    CAIResultDlg* pDlg = (CAIResultDlg*)pParam;
    if (!pDlg) return 1;

    CStringW strPromptW = L"你是一个专业的逆向工程师。下面这些汇编代码是在使用OD/xdbg这类调试器中反汇编出来的，请你分析一下这些反汇编代码的功能：\n" + (CStringW)pDlg->m_strAsmCode;

    std::string finalPromptUtf8;
    int nLen = ::WideCharToMultiByte(CP_UTF8, 0, strPromptW, -1, nullptr, 0, nullptr, nullptr);
    if (nLen > 0)
    {
        finalPromptUtf8.resize(nLen - 1);
        ::WideCharToMultiByte(CP_UTF8, 0, strPromptW, -1, &finalPromptUtf8[0], nLen - 1, nullptr, nullptr);
    }

    std::string answer = AskOllamaForHelp(finalPromptUtf8);

    int wideLen = MultiByteToWideChar(CP_UTF8, 0, answer.c_str(), -1, nullptr, 0);
    if (wideLen > 0)
    {
        wchar_t* pBuf = new wchar_t[wideLen + 1];
        MultiByteToWideChar(CP_UTF8, 0, answer.c_str(), -1, pBuf, wideLen);
        pBuf[wideLen] = L'\0'; // 确保字符串结尾安全

        ::PostMessage(pDlg->GetSafeHwnd(), WM_UPDATE_AI_TEXT, (WPARAM)pBuf, 0);
    }

    return 0;
}

LRESULT CAIResultDlg::OnUpdateText(WPARAM wParam, LPARAM lParam)
{
    wchar_t* pText = (wchar_t*)wParam;
    if (!pText) return 0;

    CRichEditCtrl* pRich = (CRichEditCtrl*)GetDlgItem(IDC_RICHEDIT_AI);
    if (!pRich)
    {
        delete[] pText;
        return 0;
    }

    pRich->SetWindowText(_T(""));

    CString strFull(pText);
    int nCurPos = 0;
    CString strLine = strFull.Tokenize(_T("\n"), nCurPos);
    bool bInCodeBlock = false;

    while (!strLine.IsEmpty() || nCurPos >= 0)
    {
        strLine.TrimRight(_T("\r"));

        if (strLine.Left(3) == _T("```"))
        {
            bInCodeBlock = !bInCodeBlock;
            AppendFormattedText(*pRich, _T("--------------------------------------------------\r\n"), RGB(200, 200, 200));
        }
        else if (bInCodeBlock)
        {
            AppendFormattedText(*pRich, strLine + _T("\r\n"), RGB(0, 128, 0), 100, false, _T("Consolas"));
        }
        else if (strLine.Left(1) == _T("#"))
        {
            int nLevel = 0;
            while (nLevel < strLine.GetLength() && strLine.GetAt(nLevel) == '#') nLevel++;
            CString content = strLine.Mid(nLevel);
            content.Trim();
            AppendFormattedText(*pRich, content + _T("\r\n"), RGB(0, 51, 153), 140 - (nLevel * 10), true);
        }
        else if (strLine.Find(_T("**")) != -1)
        {
            CString content = strLine;
            content.Replace(_T("**"), _T(""));
            AppendFormattedText(*pRich, content + _T("\r\n"), RGB(0, 0, 0), 105, true);
        }
        else
        {
            AppendFormattedText(*pRich, strLine + _T("\r\n"), RGB(60, 60, 60), 105, false);
        }

        if (nCurPos < 0) break;
        strLine = strFull.Tokenize(_T("\n"), nCurPos);
    }

    delete[] pText;
    return 0;
}