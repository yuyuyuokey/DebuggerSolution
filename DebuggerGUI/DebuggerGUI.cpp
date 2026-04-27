#include "pch.h"
#include "framework.h"
#include "DebuggerGUI.h"
#include "DebuggerGUIDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

BEGIN_MESSAGE_MAP(CDebuggerGUIApp, CWinApp)
    ON_COMMAND(ID_HELP, &CWinApp::OnHelp)
END_MESSAGE_MAP()

CDebuggerGUIApp::CDebuggerGUIApp()
{
    m_dwRestartManagerSupportFlags = AFX_RESTART_MANAGER_SUPPORT_RESTART;
}

CDebuggerGUIApp theApp;

BOOL CDebuggerGUIApp::InitInstance()
{
    // 初始化 RichEdit 控件，这是 AI 分析报告窗口 (CAIResultDlg) 必须的组件
    AfxInitRichEdit2();

    INITCOMMONCONTROLSEX InitCtrls;
    InitCtrls.dwSize = sizeof(InitCtrls);
    InitCtrls.dwICC = ICC_WIN95_CLASSES;
    InitCommonControlsEx(&InitCtrls);

    CWinApp::InitInstance();
    AfxEnableControlContainer();

    CShellManager* pShellManager = new CShellManager;

    // 激活 Windows Native 视觉管理器，启用现代控件主题
    CMFCVisualManager::SetDefaultManager(RUNTIME_CLASS(CMFCVisualManagerWindows));

    // 更改用于存储设置的注册表项
    SetRegistryKey(_T("Debugger_Gemini"));

    CDebuggerGUIDlg dlg;
    m_pMainWnd = &dlg;
    INT_PTR nResponse = dlg.DoModal();

    if (nResponse == IDOK)
    {
    }
    else if (nResponse == IDCANCEL)
    {
    }
    else if (nResponse == -1)
    {
        TRACE(traceAppMsg, 0, "警告: 对话框创建失败，应用程序将意外终止。\n");
    }

    if (pShellManager != nullptr)
    {
        delete pShellManager;
    }

#if !defined(_AFXDLL) && !defined(_AFX_NO_MFC_CONTROLS_IN_DIALOGS)
    ControlBarCleanUp();
#endif

    // 返回 FALSE 以便退出应用程序，而不是启动应用程序的消息泵
    return FALSE;
}