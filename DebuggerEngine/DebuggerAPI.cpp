#define DEBUGGER_ENGINE_EXPORTS
#include "DebuggerAPI.h"
#include "CMyDebug.h"
#include <process.h>

// 全局变量维护调试器状态
CMyDebug g_Debugger;
DEBUG_EVENT_CALLBACK g_UICallback = NULL;
HANDLE g_hResumeEvent = NULL;   // 用于挂起和唤醒调试引擎的事件
wchar_t g_TargetPath[MAX_PATH] = { 0 };

// ========================================================
// 【引擎挂起核心】当内核想索取用户输入时，就会进入这里
// ========================================================
void EnginePausedCallback(CMyDebug* dbg)
{
    // 1. 告诉 MFC 界面：“我停下来了！”
    if (g_UICallback) {
        g_UICallback(DBG_EVENT_PAUSED, dbg->GetCurrentThreadId());
    }

    // 2. 核心魔法：将当前后台线程挂起休眠，无限期等待，直到 g_hResumeEvent 被触发！
    WaitForSingleObject(g_hResumeEvent, INFINITE);
}

// 后台工作线程函数
unsigned __stdcall DebuggerThread(void* param)
{
    // 绑定挂起回调函数
    g_Debugger.SetPromptCallback(EnginePausedCallback);

    // 启动调试死循环（此时运行在后台，不会卡死UI）
    g_Debugger.BeginDebug(g_TargetPath);

    // 调试结束通知UI
    if (g_UICallback) {
        g_UICallback(DBG_EVENT_EXITED, 0);
    }
    return 0;
}

// ========================================================
// 导出给 MFC 调用的接口
// ========================================================
DBG_API bool dbg_Start(const wchar_t* targetPath, DEBUG_EVENT_CALLBACK cb)
{
    g_UICallback = cb;
    wcscpy_s(g_TargetPath, MAX_PATH, targetPath);

    // 创建一个自动重置的事件对象 (默认无信号状态)
    if (g_hResumeEvent == NULL) {
        g_hResumeEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    }

    // 启动后台线程
    _beginthreadex(NULL, 0, DebuggerThread, NULL, 0, NULL);
    return true;
}

DBG_API void dbg_Go()
{
    g_Debugger.SetUserStepping(FALSE);
    // 触发事件，唤醒后台线程继续运行！
    SetEvent(g_hResumeEvent);
}

DBG_API void dbg_StepInto()
{
    g_Debugger.SetUserStepping(TRUE);
    g_Debugger.SetStep();
    // 触发事件，唤醒后台线程执行单步！
    SetEvent(g_hResumeEvent);
}

// ========================================================
// 获取指定线程的寄存器上下文
// ========================================================
DBG_API bool dbg_GetRegs(DWORD dwThreadId, RegInfo* outRegInfo)
{
    if (!outRegInfo) return false;

    // 打开目标线程
    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT, FALSE, dwThreadId);
    if (!hThread) return false;

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL; // 获取全部通用寄存器和控制寄存器

    if (GetThreadContext(hThread, &ctx)) {
        outRegInfo->eax = ctx.Eax;
        outRegInfo->ebx = ctx.Ebx;
        outRegInfo->ecx = ctx.Ecx;
        outRegInfo->edx = ctx.Edx;
        outRegInfo->esi = ctx.Esi;
        outRegInfo->edi = ctx.Edi;
        outRegInfo->ebp = ctx.Ebp;
        outRegInfo->esp = ctx.Esp;
        outRegInfo->eip = ctx.Eip;
        outRegInfo->eflags = ctx.EFlags;

        CloseHandle(hThread);
        return true;
    }

    CloseHandle(hThread);
    return false;
}

DBG_API void dbg_StepOver()
{
    g_Debugger.SetUserStepping(TRUE);
    g_Debugger.SetStepOver(); // 你的 CMyDebug 里面写好的基于 Zydis 解析 CALL 的步过逻辑
    SetEvent(g_hResumeEvent);
}

DBG_API bool dbg_GetDisasm(DWORD dwThreadId, DWORD dwAddress, int nLines, char* outBuffer, int bufferSize)
{
    if (!outBuffer || bufferSize <= 0) return false;
    int count = g_Debugger.GetDisasm().GetDisasmString(g_Debugger.GetProcessHandle(), dwAddress, nLines, dwThreadId, outBuffer, bufferSize);
    return count > 0;
}

DBG_API bool dbg_GetDisasmList(DWORD dwThreadId, DWORD dwAddress, int nLines, InstrInfo* outBuffer, int* outCount)
{
    if (!outBuffer || !outCount) return false;
    *outCount = g_Debugger.GetDisasm().GetDisasmList(g_Debugger.GetProcessHandle(), dwAddress, nLines, dwThreadId, outBuffer);
    return (*outCount) > 0;
}

DBG_API bool dbg_SetBreakpoint(DWORD address)
{
    g_Debugger.GetBPMgr().SetBP(address);
    return true;
}

DBG_API bool dbg_RemoveBreakpoint(DWORD address)
{
    g_Debugger.GetBPMgr().RemoveBP(address);
    return true;
}

DBG_API int dbg_GetGlobalDisasmCount() {
    return g_Debugger.GetDisasm().GetGlobalCount();
}
DBG_API bool dbg_GetGlobalDisasmItem(int index, InstrInfo* outInfo) {
    return g_Debugger.GetDisasm().GetGlobalItem(index, outInfo);
}
DBG_API int dbg_FindDisasmIndexByAddr(DWORD addr) {
    return g_Debugger.GetDisasm().FindIndexByAddress(addr);
}

DBG_API void dbg_EnsureDisasm(DWORD addr) {
    g_Debugger.GetDisasm().EnsureDisasmForAddress(g_Debugger.GetProcessHandle(), addr);
}

// ========================================================
// 修改指定线程的寄存器数据
// ========================================================
DBG_API bool dbg_SetRegister(DWORD dwThreadId, const char* regName, DWORD value)
{
    // 获取线程最高权限
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadId);
    if (!hThread) return false;

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;
    if (GetThreadContext(hThread, &ctx)) {

        // 匹配寄存器名字并覆盖数据
        if (_stricmp(regName, "EAX") == 0) ctx.Eax = value;
        else if (_stricmp(regName, "EBX") == 0) ctx.Ebx = value;
        else if (_stricmp(regName, "ECX") == 0) ctx.Ecx = value;
        else if (_stricmp(regName, "EDX") == 0) ctx.Edx = value;
        else if (_stricmp(regName, "ESI") == 0) ctx.Esi = value;
        else if (_stricmp(regName, "EDI") == 0) ctx.Edi = value;
        else if (_stricmp(regName, "EBP") == 0) ctx.Ebp = value;
        else if (_stricmp(regName, "ESP") == 0) ctx.Esp = value;
        else if (_stricmp(regName, "EIP") == 0) ctx.Eip = value;
        else if (_stricmp(regName, "EFL") == 0) ctx.EFlags = value;
        else { CloseHandle(hThread); return false; }

        // 把篡改后的上下文强行塞回给 CPU
        SetThreadContext(hThread, &ctx);
    }
    CloseHandle(hThread);
    return true;
}

// ========================================================
// 读取目标进程内存数据
// ========================================================
DBG_API bool dbg_ReadMemory(DWORD address, void* buffer, SIZE_T size)
{
    SIZE_T bytesRead = 0;
    if (ReadProcessMemory(g_Debugger.GetProcessHandle(), (LPCVOID)address, buffer, size, &bytesRead)) {
        return bytesRead > 0;
    }
    return false;
}

// ========================================================
// 断点查询接口
// ========================================================
DBG_API bool dbg_HasBreakpoint(DWORD address) {
    return g_Debugger.GetBPMgr().HasBP(address);
}
DBG_API int dbg_GetBPCount() {
    return (int)g_Debugger.GetBPMgr().GetBPCount();
}
DBG_API DWORD dbg_GetBPAddress(int index) {
    return g_Debugger.GetBPMgr().GetBPAddr(index);
}