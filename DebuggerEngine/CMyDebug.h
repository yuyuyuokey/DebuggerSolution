#pragma once
#pragma once
#include <Windows.h>
#include "CThreadManager.h"
#include "CBreakpointManager.h"
#include "CDisassembler.h"

// 定义回调类型，向外部索取用户指令
class CMyDebug;
typedef void (*PromptCallback)(CMyDebug*);

class CMyDebug
{
public:
    CMyDebug();
    ~CMyDebug();

    int BeginDebug(LPCWSTR lpPath);
    void SetPromptCallback(PromptCallback cb);

    // 获取子模块和状态
    CBreakpointManager& GetBPMgr() { return m_BPMgr; }
    CDisassembler& GetDisasm() { return m_Disasm; }
    HANDLE GetProcessHandle() const { return m_hProcess; }
    DWORD GetCurrentThreadId() const { return m_DebugEvent.dwThreadId; }

    // 核心执行控制 API
    void SetUserStepping(BOOL isStepping);
    int SetStep();
    int SetStepOver();

    // 工具 API
    int ShowRegisters();
    void DumpMemory(DWORD dwAddr, int length);
    void ShowStackTrace(int nMaxFrames = 20);

private:
    int OnDebugEvent();
    int OnCreateThread();
    int OnCreateProcess();
    int OnExitProcess();
    int OnExitThread();
    int OnloadDll();
    int OnUnloadDll();
    int OnOutPutDebugString();
    int OnExecBreakPoint();

    void PrintEFlags(DWORD eflags);

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