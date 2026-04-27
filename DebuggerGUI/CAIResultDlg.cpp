#include "pch.h"
#include "DebuggerGUI.h"
#include "afxdialogex.h"
#include "CAIResultDlg.h"
#include "httplib.h"
#include "json.hpp"

// 👇 添加这一行，声明外部函数
extern std::string AskOllamaForHelp(const std::string& prompt_text);


// CAIResultDlg 对话框

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
	ON_MESSAGE(WM_UPDATE_AI_TEXT, &CAIResultDlg::OnUpdateText) // 👈 确保这里有这一行
END_MESSAGE_MAP()

// 辅助函数：向 RichEdit 插入带样式的文字
void AppendText(CRichEditCtrl& ctrl, LPCTSTR lpszText, COLORREF color = RGB(0, 0, 0), int nFontSize = 105, bool bBold = false, LPCTSTR lpszFont = _T("微软雅黑"))
{
	CHARFORMAT2 cf;
	ZeroMemory(&cf, sizeof(cf));
	cf.cbSize = sizeof(cf);
	cf.dwMask = CFM_COLOR | CFM_SIZE | CFM_BOLD | CFM_FACE;
	cf.crTextColor = color;
	cf.yHeight = nFontSize * 2; // RichEdit 字体大小单位是 1/20 磅
	cf.dwEffects = bBold ? CFE_BOLD : 0;
	_tcscpy_s(cf.szFaceName, lpszFont);

	int nLen = ctrl.GetWindowTextLength();
	ctrl.SetSel(nLen, nLen); // 选中末尾
	ctrl.SetSelectionCharFormat(cf); // 设置样式
	ctrl.ReplaceSel(lpszText); // 插入文字
}

BOOL CAIResultDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 1. 设置字体
	m_fontContent.CreatePointFont(105, _T("微软雅黑"));

	// 2. 获取控件指针（不使用 Subclass，直接用 ID 获取）
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

	// 3. 启动线程
	AfxBeginThread(AIWorkerThread, this);

	return TRUE;
}

UINT __cdecl CAIResultDlg::AIWorkerThread(LPVOID pParam)
{
	CAIResultDlg* pDlg = (CAIResultDlg*)pParam;
	if (!pDlg) return 1;

	// 构造 Prompt
	CStringW strPromptW = L"你是一个专业的逆向工程师。下面这些汇编代码是在使用OD/xdbg这类调试器中反汇编出来的，请你分析一下这些反汇编代码的功能：\n" + (CStringW)pDlg->m_strAsmCode;

	std::string finalPromptUtf8;
	int nLen = ::WideCharToMultiByte(CP_UTF8, 0, strPromptW, -1, NULL, 0, NULL, NULL);
	finalPromptUtf8.resize(nLen - 1);
	::WideCharToMultiByte(CP_UTF8, 0, strPromptW, -1, &finalPromptUtf8[0], nLen - 1, NULL, NULL);

	// 调用 AI
	std::string answer = AskOllamaForHelp(finalPromptUtf8);

	// 转回宽字符
	int wideLen = MultiByteToWideChar(CP_UTF8, 0, answer.c_str(), -1, NULL, 0);
	wchar_t* pBuf = new wchar_t[wideLen + 1];
	MultiByteToWideChar(CP_UTF8, 0, answer.c_str(), -1, pBuf, wideLen);

	// 通知界面更新
	::PostMessage(pDlg->GetSafeHwnd(), WM_UPDATE_AI_TEXT, (WPARAM)pBuf, 0);

	return 0;
}

void AppendFormattedText(CRichEditCtrl& ctrl, LPCTSTR lpszText, COLORREF color = RGB(0, 0, 0), int nFontSize = 105, bool bBold = false, LPCTSTR lpszFont = _T("微软雅黑"))
{
	CHARFORMAT2 cf;
	ZeroMemory(&cf, sizeof(cf));
	cf.cbSize = sizeof(cf);
	cf.dwMask = CFM_COLOR | CFM_SIZE | CFM_BOLD | CFM_FACE;
	cf.crTextColor = color;
	cf.yHeight = nFontSize * 2; // RichEdit 单位是 1/20 磅，所以 10.5pt 传 210
	cf.dwEffects = bBold ? CFE_BOLD : 0;
	_tcscpy_s(cf.szFaceName, lpszFont);

	int nLen = ctrl.GetWindowTextLength();
	ctrl.SetSel(nLen, nLen); // 移动到末尾
	ctrl.SetSelectionCharFormat(cf); // 应用样式
	ctrl.ReplaceSel(lpszText); // 插入文本
}

LRESULT CAIResultDlg::OnUpdateText(WPARAM wParam, LPARAM lParam)
{
	wchar_t* pText = (wchar_t*)wParam;
	CRichEditCtrl* pRich = (CRichEditCtrl*)GetDlgItem(IDC_RICHEDIT_AI);
	if (!pRich || !pText) return 0;

	pRich->SetWindowText(_T("")); // 清空等待提示

	CString strFull(pText);
	int nCurPos = 0;
	CString strLine = strFull.Tokenize(_T("\n"), nCurPos);
	bool bInCodeBlock = false;

	while (!strLine.IsEmpty() || nCurPos >= 0)
	{
		strLine.TrimRight(_T("\r"));

		// 1. 代码块渲染 (```)
		if (strLine.Left(3) == _T("```")) {
			bInCodeBlock = !bInCodeBlock;
			// 插入一条分割线
			AppendFormattedText(*pRich, _T("--------------------------------------------------\r\n"), RGB(200, 200, 200));
		}
		else if (bInCodeBlock) {
			// 代码块内部：绿色，等宽字体
			AppendFormattedText(*pRich, strLine + _T("\r\n"), RGB(0, 128, 0), 100, false, _T("Consolas"));
		}
		// 2. 标题渲染 (#)
		else if (strLine.Left(1) == _T("#")) {
			int nLevel = 0;
			while (nLevel < strLine.GetLength() && strLine.GetAt(nLevel) == '#') nLevel++;
			CString content = strLine.Mid(nLevel);
			content.Trim();
			// 标题样式：深蓝色，加粗，大字号
			AppendFormattedText(*pRich, content + _T("\r\n"), RGB(0, 51, 153), 140 - (nLevel * 10), true);
		}
		// 3. 加粗渲染 (**)
		else if (strLine.Find(_T("**")) != -1) {
			CString content = strLine;
			content.Replace(_T("**"), _T("")); // 简单去除标记，整行加粗
			AppendFormattedText(*pRich, content + _T("\r\n"), RGB(0, 0, 0), 105, true);
		}
		// 4. 普通文本
		else {
			AppendFormattedText(*pRich, strLine + _T("\r\n"), RGB(60, 60, 60), 105, false);
		}

		if (nCurPos < 0) break;
		strLine = strFull.Tokenize(_T("\n"), nCurPos);
	}

	delete[] pText;
	return 0;
}
