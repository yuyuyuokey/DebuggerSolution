#define _CRT_SECURE_NO_WARNINGS
#include "CMyDebug.h"
#include <stdio.h>

CMyDebug::CMyDebug()
    : m_IsSystemBreakPoint(FALSE)
    , m_hProcess(NULL)
    , m_pPromptCallback(NULL)
    , m_dwStepOverBPAddr(0)
    , m_bIsUserStepping(FALSE)
    , m_dwStepOverTempBPAddr(0)
    , m_TempBPOrigByte(0)
    , m_bRunning(TRUE)
{
}

CMyDebug::~CMyDebug() { if (m_hProcess) CloseHandle(m_hProcess); }

void CMyDebug::SetPromptCallback(PromptCallback cb) { m_pPromptCallback = cb; }

int CMyDebug::BeginDebug(LPCWSTR lpPath) {
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    if (!CreateProcessW(lpPath, NULL, NULL, NULL, FALSE, DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi)) { return 0; }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return EventLoop();
}

int CMyDebug::AttachDebug(DWORD dwPID) {
    if (!DebugActiveProcess(dwPID)) return 0;
    DebugSetProcessKillOnExit(FALSE);
    return EventLoop();
}

int CMyDebug::EventLoop() {
    m_bRunning = TRUE;
    m_IsSystemBreakPoint = FALSE;
    while (m_bRunning) {
        if (!WaitForDebugEvent(&m_DebugEvent, INFINITE)) break;
        DWORD dwContinueStatus = DBG_CONTINUE;

        switch (m_DebugEvent.dwDebugEventCode) {
        case EXCEPTION_DEBUG_EVENT:    dwContinueStatus = OnDebugEvent(); break;
        case CREATE_PROCESS_DEBUG_EVENT:dwContinueStatus = OnCreateProcess(); break;
        case CREATE_THREAD_DEBUG_EVENT: dwContinueStatus = OnCreateThread(); break;
        case EXIT_PROCESS_DEBUG_EVENT:  dwContinueStatus = OnExitProcess(); break;
        case EXIT_THREAD_DEBUG_EVENT:   dwContinueStatus = OnExitThread(); break;
        case LOAD_DLL_DEBUG_EVENT:      dwContinueStatus = OnloadDll(); break;
        case UNLOAD_DLL_DEBUG_EVENT:    dwContinueStatus = OnUnloadDll(); break;
        case OUTPUT_DEBUG_STRING_EVENT: dwContinueStatus = OnOutPutDebugString(); break;
        }

        if (!ContinueDebugEvent(m_DebugEvent.dwProcessId, m_DebugEvent.dwThreadId, dwContinueStatus)) break;
    }
    return 1;
}

int CMyDebug::OnDebugEvent() {
    EXCEPTION_RECORD* pInfo = &m_DebugEvent.u.Exception.ExceptionRecord;
    switch (pInfo->ExceptionCode) {
    case EXCEPTION_ACCESS_VIOLATION:
        return DBG_EXCEPTION_NOT_HANDLED;

    case EXCEPTION_BREAKPOINT:
        return OnExecBreakPoint();

    case EXCEPTION_SINGLE_STEP: {
        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, m_DebugEvent.dwThreadId);
        CONTEXT ctx = { 0 }; ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
        GetThreadContext(hThread, &ctx);

        if (ctx.Dr6 & 0x0F) {
            ctx.Dr6 = 0; ctx.EFlags |= 0x10000; SetThreadContext(hThread, &ctx);
            if (m_pPromptCallback) m_pPromptCallback(DBG_EVENT_PAUSED, m_DebugEvent.dwThreadId);
            CloseHandle(hThread); return DBG_CONTINUE;
        }
        if (m_dwStepOverBPAddr != 0) {
            BYTE cc = 0xCC; WriteProcessMemory(m_hProcess, (LPVOID)m_dwStepOverBPAddr, &cc, 1, NULL);
            FlushInstructionCache(m_hProcess, (LPVOID)m_dwStepOverBPAddr, 1);
            m_dwStepOverBPAddr = 0;
        }

        if (!m_bIsUserStepping) { CloseHandle(hThread); return DBG_CONTINUE; }
        m_bIsUserStepping = FALSE;
        if (m_pPromptCallback) m_pPromptCallback(DBG_EVENT_PAUSED, m_DebugEvent.dwThreadId);
        CloseHandle(hThread); return DBG_CONTINUE;
    }
    }
    return DBG_EXCEPTION_NOT_HANDLED;
}

int CMyDebug::OnExecBreakPoint() {
    DWORD dwExAddr = (DWORD)m_DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
    if (!m_IsSystemBreakPoint) {
        m_IsSystemBreakPoint = TRUE;
        if (m_pPromptCallback) m_pPromptCallback(DBG_EVENT_PAUSED, m_DebugEvent.dwThreadId);
        return DBG_CONTINUE;
    }
    if (dwExAddr == m_dwStepOverTempBPAddr) {
        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, m_DebugEvent.dwThreadId);
        CONTEXT ctx = { 0 }; ctx.ContextFlags = CONTEXT_CONTROL; GetThreadContext(hThread, &ctx);
        ctx.Eip = dwExAddr; SetThreadContext(hThread, &ctx);
        WriteProcessMemory(m_hProcess, (LPVOID)dwExAddr, &m_TempBPOrigByte, 1, NULL);
        FlushInstructionCache(m_hProcess, (LPVOID)dwExAddr, 1);
        m_dwStepOverTempBPAddr = 0;
        if (m_pPromptCallback) m_pPromptCallback(DBG_EVENT_PAUSED, m_DebugEvent.dwThreadId);
        CloseHandle(hThread); return DBG_CONTINUE;
    }
    if (m_BPMgr.HasBP(dwExAddr)) {
        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, m_DebugEvent.dwThreadId);
        CONTEXT ctx = { 0 }; ctx.ContextFlags = CONTEXT_CONTROL; GetThreadContext(hThread, &ctx);
        ctx.Eip = dwExAddr; ctx.EFlags |= 0x100; SetThreadContext(hThread, &ctx);
        BYTE orig = m_BPMgr.GetOriginalByte(dwExAddr);
        WriteProcessMemory(m_hProcess, (LPVOID)dwExAddr, &orig, 1, NULL);
        FlushInstructionCache(m_hProcess, (LPVOID)dwExAddr, 1);
        m_dwStepOverBPAddr = dwExAddr;
        if (m_pPromptCallback) m_pPromptCallback(DBG_EVENT_PAUSED, m_DebugEvent.dwThreadId);
        CloseHandle(hThread); return DBG_CONTINUE;
    }
    return DBG_EXCEPTION_NOT_HANDLED;
}

int CMyDebug::OnCreateThread() { m_ThreadMgr.AddThread(m_DebugEvent.dwThreadId); return DBG_CONTINUE; }
int CMyDebug::OnCreateProcess() {
    m_hProcess = m_DebugEvent.u.CreateProcessInfo.hProcess;
    m_Disasm.Init(); m_ThreadMgr.AddThread(m_DebugEvent.dwThreadId);
    m_BPMgr.Init(m_hProcess, &m_ThreadMgr);
    m_Disasm.BuildGlobalDisasm(m_hProcess, (DWORD)m_DebugEvent.u.CreateProcessInfo.lpBaseOfImage);
    return DBG_CONTINUE;
}

int CMyDebug::OnExitProcess() { m_bRunning = FALSE; return DBG_CONTINUE; }
int CMyDebug::OnExitThread() { m_ThreadMgr.RemoveThread(m_DebugEvent.dwThreadId); return DBG_CONTINUE; }
int CMyDebug::OnloadDll() { return DBG_CONTINUE; }
int CMyDebug::OnUnloadDll() { return DBG_CONTINUE; }
int CMyDebug::OnOutPutDebugString() { return DBG_CONTINUE; }
void CMyDebug::SetUserStepping(BOOL isStepping) { m_bIsUserStepping = isStepping; }
int CMyDebug::SetStep() {
    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, m_DebugEvent.dwThreadId);
    if (!hThread) return 0;
    CONTEXT ctx = { 0 }; ctx.ContextFlags = CONTEXT_CONTROL;
    if (GetThreadContext(hThread, &ctx)) { ctx.EFlags |= 0x100; SetThreadContext(hThread, &ctx); }
    CloseHandle(hThread); return 1;
}

int CMyDebug::SetStepOver() {
    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT, FALSE, m_DebugEvent.dwThreadId);
    CONTEXT ctx = { 0 }; ctx.ContextFlags = CONTEXT_CONTROL; GetThreadContext(hThread, &ctx); CloseHandle(hThread);
    BYTE buffer[16] = { 0 }; SIZE_T rb = 0; ReadProcessMemory(m_hProcess, (LPCVOID)ctx.Eip, buffer, sizeof(buffer), &rb);
    DWORD instrLen = 0;
    if (m_Disasm.IsCallInstruction(buffer, rb, instrLen)) {
        DWORD nextAddr = ctx.Eip + instrLen;
        ReadProcessMemory(m_hProcess, (LPCVOID)nextAddr, &m_TempBPOrigByte, 1, NULL);
        BYTE cc = 0xCC; WriteProcessMemory(m_hProcess, (LPVOID)nextAddr, &cc, 1, NULL);
        FlushInstructionCache(m_hProcess, (LPCVOID)nextAddr, 1);
        m_dwStepOverTempBPAddr = nextAddr;
        return 1;
    }
    return SetStep();
}