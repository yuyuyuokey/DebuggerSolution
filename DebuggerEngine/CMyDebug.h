#pragma once
#include <Windows.h>
#include "CThreadManager.h"
#include "CBreakpointManager.h"
#include "CDisassembler.h"

class CMyDebug;
typedef void(__stdcall* PromptCallback)(int eventType, DWORD dwThreadId);

class CMyDebug
{
public:
    CMyDebug();
    ~CMyDebug();

    int BeginDebug(LPCWSTR lpPath);
    int AttachDebug(DWORD dwPID);

    void SetPromptCallback(PromptCallback cb);
    CBreakpointManager& GetBPMgr() { return m_BPMgr; }
    CDisassembler& GetDisasm() { return m_Disasm; }
    HANDLE GetProcessHandle() const { return m_hProcess; }
    DWORD GetCurrentThreadId() const { return m_DebugEvent.dwThreadId; }

    void SetUserStepping(BOOL isStepping);
    int SetStep();
    int SetStepOver();

    // 剔除了在重构剥离成窗格化后根本不再属于基核作用并引生报错和崩溃的老旧文本调试辅助。保留架构基础核心：
private:
    int EventLoop();

    int OnDebugEvent();
    int OnCreateThread();
    int OnCreateProcess();
    int OnExitProcess();
    int OnExitThread();
    int OnloadDll();
    int OnUnloadDll();
    int OnOutPutDebugString();
    int OnExecBreakPoint();

private:
    BOOL m_bRunning;
    DEBUG_EVENT m_DebugEvent;
    BOOL m_IsSystemBreakPoint;
    HANDLE m_hProcess;

    PromptCallback m_pPromptCallback;

    CThreadManager m_ThreadMgr;
    CBreakpointManager m_BPMgr;
    CDisassembler m_Disasm;

    DWORD m_dwStepOverBPAddr;
    BOOL  m_bIsUserStepping;
    DWORD m_dwStepOverTempBPAddr;
    BYTE  m_TempBPOrigByte;
};