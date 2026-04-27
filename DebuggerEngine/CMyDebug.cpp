#define _CRT_SECURE_NO_WARNINGS
#include "CMyDebug.h"
#include <stdio.h>

CMyDebug::CMyDebug()
    : m_hProcess(NULL)
    , m_hThread(NULL)
    , m_bRunning(TRUE)
    , m_dwUserImageBase(0)
    , m_dwUserImageSize(0)
    , m_IsSystemBreakPoint(FALSE)
    , m_bIsUserStepping(FALSE)
    , m_dwStepOverBPAddr(0)
    , m_dwStepOverTempBPAddr(0)
    , m_TempBPOrigByte(0)
    , m_dwRunToRetAddr(0)
    , m_pPromptCallback(NULL)
{
    ZeroMemory(&m_DebugEvent, sizeof(m_DebugEvent));
}

CMyDebug::~CMyDebug()
{
    if (m_hProcess)
    {
        CloseHandle(m_hProcess);
        m_hProcess = NULL;
    }
}

void CMyDebug::SetPromptCallback(PromptCallback cb)
{
    m_pPromptCallback = cb;
}

int CMyDebug::BeginDebug(LPCWSTR lpPath)
{
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    BOOL bRet = CreateProcessW(
        lpPath, NULL, NULL, NULL, FALSE,
        DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS,
        NULL, NULL, &si, &pi
    );

    if (!bRet) return 0;

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return EventLoop();
}

int CMyDebug::AttachDebug(DWORD dwPID)
{
    if (!DebugActiveProcess(dwPID)) return 0;

    DebugSetProcessKillOnExit(FALSE);
    return EventLoop();
}

int CMyDebug::EventLoop()
{
    m_bRunning = TRUE;
    while (m_bRunning)
    {
        if (!WaitForDebugEvent(&m_DebugEvent, INFINITE))
            break;

        int dwContinueStatus = OnDebugEvent();

        if (m_DebugEvent.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
        {
            ContinueDebugEvent(m_DebugEvent.dwProcessId, m_DebugEvent.dwThreadId, DBG_CONTINUE);
            break;
        }
        ContinueDebugEvent(m_DebugEvent.dwProcessId, m_DebugEvent.dwThreadId, dwContinueStatus);
    }
    return 1;
}

int CMyDebug::OnDebugEvent()
{
    switch (m_DebugEvent.dwDebugEventCode)
    {
    case EXCEPTION_DEBUG_EVENT:
        if (m_DebugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT)
        {
            return OnExecBreakPoint();
        }
        else if (m_DebugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP)
        {
            if (m_pPromptCallback)
                m_pPromptCallback(DBG_EVENT_PAUSED, m_DebugEvent.dwThreadId);
            return DBG_CONTINUE;
        }
        return DBG_EXCEPTION_NOT_HANDLED;

    case CREATE_THREAD_DEBUG_EVENT:   return OnCreateThread();
    case CREATE_PROCESS_DEBUG_EVENT:  return OnCreateProcess();
    case EXIT_THREAD_DEBUG_EVENT:     return OnExitThread();
    case EXIT_PROCESS_DEBUG_EVENT:    return OnExitProcess();
    case LOAD_DLL_DEBUG_EVENT:        return OnloadDll();
    case UNLOAD_DLL_DEBUG_EVENT:      return OnUnloadDll();
    case OUTPUT_DEBUG_STRING_EVENT:   return OnOutPutDebugString();
    default:                          return DBG_CONTINUE;
    }
}

int CMyDebug::OnCreateThread()
{
    m_ThreadMgr.AddThread(m_DebugEvent.dwThreadId);
    return DBG_CONTINUE;
}

int CMyDebug::OnCreateProcess()
{
    m_hProcess = m_DebugEvent.u.CreateProcessInfo.hProcess;
    m_dwUserImageBase = (DWORD)m_DebugEvent.u.CreateProcessInfo.lpBaseOfImage;

    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS32 ntHeaders; // 修正逻辑：明确使用32位结构体避免越界
    if (ReadProcessMemory(m_hProcess, (LPCVOID)m_dwUserImageBase, &dosHeader, sizeof(dosHeader), NULL))
    {
        if (ReadProcessMemory(m_hProcess, (LPCVOID)(m_dwUserImageBase + dosHeader.e_lfanew), &ntHeaders, sizeof(ntHeaders), NULL))
        {
            m_dwUserImageSize = ntHeaders.OptionalHeader.SizeOfImage;
        }
    }

    // 清理上一个进程的调试状态残留
    m_dwStepOverBPAddr = 0;
    m_dwStepOverTempBPAddr = 0;
    m_IsSystemBreakPoint = FALSE;
    m_bIsUserStepping = FALSE;

    // 初始化核心组件
    m_Disasm.Init();
    m_ThreadMgr.AddThread(m_DebugEvent.dwThreadId);
    m_BPMgr.Init(m_hProcess, &m_ThreadMgr);
    m_Disasm.BuildGlobalDisasm(m_hProcess, m_dwUserImageBase);

    return DBG_CONTINUE;
}

int CMyDebug::OnExitProcess()
{
    m_bRunning = FALSE;
    if (m_pPromptCallback)
        m_pPromptCallback(DBG_EVENT_EXITED, 0);
    return DBG_CONTINUE;
}

int CMyDebug::OnExitThread()
{
    m_ThreadMgr.RemoveThread(m_DebugEvent.dwThreadId);
    return DBG_CONTINUE;
}

int CMyDebug::OnloadDll() { return DBG_CONTINUE; }
int CMyDebug::OnUnloadDll() { return DBG_CONTINUE; }
int CMyDebug::OnOutPutDebugString() { return DBG_CONTINUE; }

void CMyDebug::SetUserStepping(BOOL isStepping)
{
    m_bIsUserStepping = isStepping;
}

int CMyDebug::SetStep()
{
    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, m_DebugEvent.dwThreadId);
    if (!hThread) return 0;

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_CONTROL;

    if (GetThreadContext(hThread, &ctx))
    {
        ctx.EFlags |= 0x100; // 设置 Trap Flag(TF) 进入单步模式
        SetThreadContext(hThread, &ctx);
    }

    CloseHandle(hThread);
    return 1;
}

int CMyDebug::SetStepOver()
{
    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT, FALSE, m_DebugEvent.dwThreadId);
    if (!hThread) return 0;

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_CONTROL;
    GetThreadContext(hThread, &ctx);
    CloseHandle(hThread);

    BYTE buffer[16] = { 0 };
    SIZE_T rb = 0;
    ReadProcessMemory(m_hProcess, (LPCVOID)ctx.Eip, buffer, sizeof(buffer), &rb);

    DWORD instrLen = 0;
    if (m_Disasm.IsCallInstruction(buffer, rb, instrLen))
    {
        DWORD nextAddr = ctx.Eip + instrLen;
        SetTempBreakpoint(nextAddr); // 优化逻辑：复用临时断点函数
        return 1;
    }
    return SetStep();
}

void CMyDebug::SetTempBreakpoint(DWORD dwAddr)
{
    if (!m_hProcess || dwAddr == 0) return;

    // 读出原始指令字节并保存
    ReadProcessMemory(m_hProcess, (LPCVOID)dwAddr, &m_TempBPOrigByte, 1, NULL);

    // 写入 INT 3 (0xCC) 制造断点
    BYTE cc = 0xCC;
    WriteProcessMemory(m_hProcess, (LPVOID)dwAddr, &cc, 1, NULL);
    FlushInstructionCache(m_hProcess, (LPCVOID)dwAddr, 1);

    m_dwStepOverTempBPAddr = dwAddr;
}

int CMyDebug::OnExecBreakPoint()
{
    DWORD dwExAddr = (DWORD)m_DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress;

    // 1. 处理系统启动时自动产生的断点
    if (!m_IsSystemBreakPoint)
    {
        m_IsSystemBreakPoint = TRUE;
        if (m_pPromptCallback)
            m_pPromptCallback(DBG_EVENT_PAUSED, m_DebugEvent.dwThreadId);
        return DBG_CONTINUE;
    }

    // 2. 处理 StepOver 等一次性临时断点
    if (dwExAddr == m_dwStepOverTempBPAddr)
    {
        // 恢复原始字节
        WriteProcessMemory(m_hProcess, (LPVOID)dwExAddr, &m_TempBPOrigByte, 1, NULL);
        FlushInstructionCache(m_hProcess, (LPCVOID)dwExAddr, 1);

        HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, m_DebugEvent.dwThreadId);
        if (hThread)
        {
            CONTEXT ctx = { 0 };
            ctx.ContextFlags = CONTEXT_CONTROL;
            if (GetThreadContext(hThread, &ctx))
            {
                ctx.Eip--; // 回退 EIP 指向真正要执行的代码
                SetThreadContext(hThread, &ctx);
            }
            CloseHandle(hThread);
        }

        m_dwStepOverTempBPAddr = 0;
        if (m_pPromptCallback)
            m_pPromptCallback(DBG_EVENT_PAUSED, m_DebugEvent.dwThreadId);
        return DBG_CONTINUE;
    }

    // 3. 处理用户设定的全局软件断点
    if (m_BPMgr.HasBP(dwExAddr))
    {
        BYTE origByte = m_BPMgr.GetOriginalByte(dwExAddr);
        WriteProcessMemory(m_hProcess, (LPVOID)dwExAddr, &origByte, 1, NULL);
        FlushInstructionCache(m_hProcess, (LPCVOID)dwExAddr, 1);

        HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, m_DebugEvent.dwThreadId);
        if (hThread)
        {
            CONTEXT ctx = { 0 };
            ctx.ContextFlags = CONTEXT_CONTROL;
            if (GetThreadContext(hThread, &ctx))
            {
                ctx.Eip--;
                SetThreadContext(hThread, &ctx);
            }
            CloseHandle(hThread);
        }

        if (m_pPromptCallback)
            m_pPromptCallback(DBG_EVENT_PAUSED, m_DebugEvent.dwThreadId);
        return DBG_CONTINUE;
    }

    // 4. 处理手工暂停 (F12) 或者 DebugBreak 产生的游离断点
    if (m_pPromptCallback)
    {
        m_pPromptCallback(DBG_EVENT_PAUSED, m_DebugEvent.dwThreadId);
    }
    return DBG_CONTINUE;
}

// ==== 空实现占位符（相关控制逻辑由 API 层接管） ====
void CMyDebug::Stop() {}
void CMyDebug::Restart() {}
void CMyDebug::RunToReturn() {}
void CMyDebug::RunToUserCode() {}
void CMyDebug::Go() {}