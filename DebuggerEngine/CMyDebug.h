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

    // ==== 核心调试控制 ====
    int BeginDebug(LPCWSTR lpPath);
    int AttachDebug(DWORD dwPID);
    void Stop();
    void Restart();
    void RunToReturn();
    void RunToUserCode();
    void Go();

    // ==== 状态获取与设置 ====
    void SetPromptCallback(PromptCallback cb);
    CBreakpointManager& GetBPMgr() { return m_BPMgr; }
    CDisassembler& GetDisasm() { return m_Disasm; }
    HANDLE GetProcessHandle() const { return m_hProcess; }
    DWORD GetCurrentThreadId() const { return m_DebugEvent.dwThreadId; }
    DWORD GetUserImageBase() const { return m_dwUserImageBase; }
    DWORD GetUserImageSize() const { return m_dwUserImageSize; }

    // ==== 单步与断点操作 ====
    void SetUserStepping(BOOL isStepping);
    int SetStep();
    int SetStepOver();
    void SetTempBreakpoint(DWORD dwAddr); // 设置一次性临时断点

private:
    // ==== 调试事件循环与分发 ====
    int EventLoop();
    int OnDebugEvent();

    // ==== 事件处理函数 ====
    int OnCreateThread();
    int OnCreateProcess();
    int OnExitProcess();
    int OnExitThread();
    int OnloadDll();
    int OnUnloadDll();
    int OnOutPutDebugString();
    int OnExecBreakPoint();

private:
    // ==== 进程与线程信息 ====
    HANDLE m_hProcess;
    HANDLE m_hThread;
    DEBUG_EVENT m_DebugEvent;
    BOOL m_bRunning;

    // ==== 主模块信息 ====
    DWORD m_dwUserImageBase;
    DWORD m_dwUserImageSize;

    // ==== 断点与状态标记 ====
    BOOL m_IsSystemBreakPoint;
    BOOL m_bIsUserStepping;
    DWORD m_dwStepOverBPAddr;
    DWORD m_dwStepOverTempBPAddr;
    BYTE m_TempBPOrigByte;
    DWORD m_dwRunToRetAddr;

    // ==== 回调与管理器 ====
    PromptCallback m_pPromptCallback;
    CThreadManager m_ThreadMgr;
    CBreakpointManager m_BPMgr;
    CDisassembler m_Disasm;
};