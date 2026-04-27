#define DEBUGGER_ENGINE_EXPORTS
#include "DebuggerAPI.h"
#include "CMyDebug.h"
#include <process.h>
#include <vector>
#include <Psapi.h>

#pragma comment(lib, "psapi.lib")

CMyDebug g_Debugger;
DEBUG_EVENT_CALLBACK g_UICallback = NULL;
HANDLE g_hResumeEvent = NULL;
wchar_t g_TargetPath[MAX_PATH] = { 0 };
DWORD g_TargetPID = 0;

std::vector<MemMapItem> g_MemMap;
std::vector<CallStackItem> g_CallStack;

void __stdcall EnginePausedCallback(int eventType, DWORD dwThreadId)
{
    if (g_UICallback)
    {
        g_UICallback(eventType, dwThreadId);
    }

    if (eventType != DBG_EVENT_EXITED)
    {
        WaitForSingleObject(g_hResumeEvent, INFINITE);
    }
}

unsigned __stdcall DebuggerThread(void* param)
{
    g_Debugger.SetPromptCallback(EnginePausedCallback);

    if (g_TargetPID != 0)
    {
        g_Debugger.AttachDebug(g_TargetPID);
    }
    else
    {
        g_Debugger.BeginDebug(g_TargetPath);
    }

    if (g_UICallback)
    {
        g_UICallback(DBG_EVENT_EXITED, 0);
    }

    return 0;
}

DBG_API bool dbg_Start(const wchar_t* targetPath, DEBUG_EVENT_CALLBACK cb)
{
    g_UICallback = cb;
    g_TargetPID = 0;
    wcscpy_s(g_TargetPath, MAX_PATH, targetPath);

    if (g_hResumeEvent == NULL)
    {
        g_hResumeEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    }

    _beginthreadex(NULL, 0, DebuggerThread, NULL, 0, NULL);
    return true;
}

DBG_API bool dbg_Attach(DWORD targetPID, DEBUG_EVENT_CALLBACK cb)
{
    g_UICallback = cb;
    g_TargetPID = targetPID;
    g_TargetPath[0] = L'\0';

    if (g_hResumeEvent == NULL)
    {
        g_hResumeEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    }

    _beginthreadex(NULL, 0, DebuggerThread, NULL, 0, NULL);
    return true;
}

DBG_API void dbg_Go()
{
    g_Debugger.SetUserStepping(FALSE);
    SetEvent(g_hResumeEvent);
}

DBG_API void dbg_StepInto()
{
    g_Debugger.SetUserStepping(TRUE);
    g_Debugger.SetStep();
    SetEvent(g_hResumeEvent);
}

DBG_API void dbg_StepOver()
{
    g_Debugger.SetUserStepping(TRUE);
    g_Debugger.SetStepOver();
    SetEvent(g_hResumeEvent);
}

DBG_API void dbg_Pause()
{
    if (g_Debugger.GetProcessHandle())
    {
        DebugBreakProcess(g_Debugger.GetProcessHandle());
    }
}

DBG_API void dbg_Stop()
{
    if (g_Debugger.GetProcessHandle())
    {
        TerminateProcess(g_Debugger.GetProcessHandle(), 0);
        SetEvent(g_hResumeEvent);
    }
}

DBG_API void dbg_Restart()
{
    dbg_Stop();
}

DBG_API void dbg_RunToCursor(DWORD addr)
{
    dbg_SetBreakpoint(addr);
    dbg_Go();
}

DBG_API void dbg_RunToReturn()
{
}

DBG_API void dbg_RunToUserCode()
{
}

DBG_API bool dbg_GetRegs(DWORD dwThreadId, RegInfo* outRegInfo)
{
    if (!outRegInfo)
    {
        return false;
    }

    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT, FALSE, dwThreadId);
    if (!hThread)
    {
        return false;
    }

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;

    if (GetThreadContext(hThread, &ctx))
    {
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

DBG_API bool dbg_SetRegister(DWORD dwThreadId, const char* regName, DWORD value)
{
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadId);
    if (!hThread)
    {
        return false;
    }

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;

    if (GetThreadContext(hThread, &ctx))
    {
        if (_stricmp(regName, "EAX") == 0)
            ctx.Eax = value;
        else if (_stricmp(regName, "EBX") == 0)
            ctx.Ebx = value;
        else if (_stricmp(regName, "ECX") == 0)
            ctx.Ecx = value;
        else if (_stricmp(regName, "EDX") == 0)
            ctx.Edx = value;
        else if (_stricmp(regName, "ESI") == 0)
            ctx.Esi = value;
        else if (_stricmp(regName, "EDI") == 0)
            ctx.Edi = value;
        else if (_stricmp(regName, "EBP") == 0)
            ctx.Ebp = value;
        else if (_stricmp(regName, "ESP") == 0)
            ctx.Esp = value;
        else if (_stricmp(regName, "EIP") == 0)
            ctx.Eip = value;
        else if (_stricmp(regName, "EFL") == 0)
            ctx.EFlags = value;
        else
        {
            CloseHandle(hThread);
            return false;
        }

        SetThreadContext(hThread, &ctx);
    }

    CloseHandle(hThread);
    return true;
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

DBG_API bool dbg_HasBreakpoint(DWORD address)
{
    return g_Debugger.GetBPMgr().HasBP(address);
}

DBG_API bool dbg_SetHardwareBreakpoint(DWORD address, int type, int len)
{
    g_Debugger.GetBPMgr().SetHWBP(address, type, len);
    return true;
}

DBG_API bool dbg_RemoveHardwareBreakpoint(DWORD address)
{
    g_Debugger.GetBPMgr().RemoveHWBP(address);
    return true;
}

DBG_API bool dbg_HasHardwareBreakpoint(DWORD address)
{
    return g_Debugger.GetBPMgr().HasHWBP(address);
}

DBG_API int dbg_GetTotalBPCount()
{
    int count = (int)g_Debugger.GetBPMgr().GetBPCount();
    const HWBP_INFO* hw = g_Debugger.GetBPMgr().GetHWBPArray();

    for (int i = 0; i < 4; i++)
    {
        if (hw[i].active)
        {
            count++;
        }
    }
    return count;
}

DBG_API bool dbg_GetBPInfo(int index, BPDisplayInfo* outInfo)
{
    int swCount = (int)g_Debugger.GetBPMgr().GetBPCount();

    if (index < swCount)
    {
        outInfo->address = g_Debugger.GetBPMgr().GetBPAddr(index);
        outInfo->type = BP_TYPE_SOFTWARE;
        outInfo->length = 1;
        outInfo->active = true;
        return true;
    }

    int hwIdx = index - swCount;
    const HWBP_INFO* hw = g_Debugger.GetBPMgr().GetHWBPArray();
    int currentHw = 0;

    for (int i = 0; i < 4; i++)
    {
        if (hw[i].active)
        {
            if (currentHw == hwIdx)
            {
                outInfo->address = hw[i].dwAddr;
                outInfo->type = BP_TYPE_HW_EXECUTE + hw[i].type;
                outInfo->length = hw[i].len;
                outInfo->active = true;
                return true;
            }
            currentHw++;
        }
    }
    return false;
}

DBG_API bool dbg_ReadMemory(DWORD address, void* buffer, SIZE_T size)
{
    SIZE_T bytesRead = 0;
    if (ReadProcessMemory(g_Debugger.GetProcessHandle(), (LPCVOID)address, buffer, size, &bytesRead))
    {
        return bytesRead > 0;
    }
    return false;
}

DBG_API void dbg_EnsureDisasm(DWORD addr)
{
    g_Debugger.GetDisasm().EnsureDisasmForAddress(g_Debugger.GetProcessHandle(), addr);
}

DBG_API int dbg_GetGlobalDisasmCount()
{
    return g_Debugger.GetDisasm().GetGlobalCount();
}

DBG_API bool dbg_GetGlobalDisasmItem(int index, InstrInfo* outInfo)
{
    return g_Debugger.GetDisasm().GetGlobalItem(index, outInfo);
}

DBG_API int dbg_FindDisasmIndexByAddr(DWORD addr)
{
    return g_Debugger.GetDisasm().FindIndexByAddress(addr);
}

void ParseProtection(DWORD protect, char* outStr)
{
    strcpy_s(outStr, 16, "-R--");

    if (protect & PAGE_EXECUTE)                 strcpy_s(outStr, 16, "E---");
    else if (protect & PAGE_EXECUTE_READ)       strcpy_s(outStr, 16, "ER--");
    else if (protect & PAGE_EXECUTE_READWRITE)  strcpy_s(outStr, 16, "ERW-");
    else if (protect & PAGE_EXECUTE_WRITECOPY)  strcpy_s(outStr, 16, "ERWC");
    else if (protect & PAGE_NOACCESS)           strcpy_s(outStr, 16, "----");
    else if (protect & PAGE_READONLY)           strcpy_s(outStr, 16, "-R--");
    else if (protect & PAGE_READWRITE)          strcpy_s(outStr, 16, "-RW-");
    else if (protect & PAGE_WRITECOPY)          strcpy_s(outStr, 16, "-RWC");
}

DBG_API void dbg_UpdateMemoryMap()
{
    g_MemMap.clear();

    HANDLE hProc = g_Debugger.GetProcessHandle();
    if (!hProc) return;

    DWORD addr = 0;
    MEMORY_BASIC_INFORMATION mbi;

    while (VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi)))
    {
        MemMapItem item = { 0 };
        item.address = (DWORD)mbi.BaseAddress;
        item.size = mbi.RegionSize;

        ParseProtection(mbi.Protect, item.protection);
        ParseProtection(mbi.AllocationProtect, item.initProtect);

        if (mbi.Type == MEM_IMAGE)
        {
            char path[MAX_PATH] = { 0 };
            if (GetModuleFileNameExA(hProc, (HMODULE)mbi.AllocationBase, path, MAX_PATH))
            {
                char* pName = strrchr(path, '\\');
                strcpy_s(item.info, sizeof(item.info), pName ? pName + 1 : path);
            }
            else
            {
                strcpy_s(item.info, sizeof(item.info), "PE Image");
            }
        }
        else if (mbi.Type == MEM_MAPPED)
        {
            strcpy_s(item.info, sizeof(item.info), "Mapped");
        }
        else if (mbi.Type == MEM_PRIVATE)
        {
            strcpy_s(item.info, sizeof(item.info), "Private");
        }

        g_MemMap.push_back(item);

        DWORD nextAddr = addr + mbi.RegionSize;
        if (nextAddr <= addr)
        {
            break;
        }
        addr = nextAddr;
    }
}

DBG_API int dbg_GetMemoryMapCount()
{
    return (int)g_MemMap.size();
}

DBG_API bool dbg_GetMemoryMapItem(int index, MemMapItem* outItem)
{
    if (index < 0 || index >= g_MemMap.size() || !outItem)
    {
        return false;
    }
    *outItem = g_MemMap[index];
    return true;
}

DBG_API void dbg_UpdateCallStack(DWORD threadId)
{
    g_CallStack.clear();

    HANDLE hProc = g_Debugger.GetProcessHandle();
    if (!hProc) return;

    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT, FALSE, threadId);
    if (!hThread) return;

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(hThread, &ctx);
    CloseHandle(hThread);

    DWORD currentEbp = ctx.Ebp;

    for (int i = 0; i < 50; i++)
    {
        CallStackItem item = { 0 };
        item.ebp = currentEbp;

        DWORD retAddr = 0;
        DWORD nextEbp = 0;

        if (!ReadProcessMemory(hProc, (LPCVOID)(currentEbp + 4), &retAddr, 4, NULL)) break;
        if (!ReadProcessMemory(hProc, (LPCVOID)currentEbp, &nextEbp, 4, NULL)) break;

        item.retTo = retAddr;

        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProc, (LPCVOID)retAddr, &mbi, sizeof(mbi)) && mbi.Type == MEM_IMAGE)
        {
            char path[MAX_PATH] = { 0 };
            if (GetModuleFileNameExA(hProc, (HMODULE)mbi.AllocationBase, path, MAX_PATH))
            {
                char* pName = strrchr(path, '\\');
                strcpy_s(item.moduleName, sizeof(item.moduleName), pName ? pName + 1 : path);
            }
        }

        g_CallStack.push_back(item);

        if (nextEbp <= currentEbp || nextEbp == 0)
        {
            break;
        }
        currentEbp = nextEbp;
    }
}

DBG_API int dbg_GetCallStackCount()
{
    return (int)g_CallStack.size();
}

DBG_API bool dbg_GetCallStackItem(int index, CallStackItem* outItem)
{
    if (index < 0 || index >= g_CallStack.size() || !outItem)
    {
        return false;
    }
    *outItem = g_CallStack[index];
    return true;
}

// =========================================================================
// 核心：智能 API 地址解析引擎
// =========================================================================
DBG_API DWORD dbg_ResolveApiAddress(const char* apiName)
{
    // 定义常见的系统核心模块列表
    const char* commonModules[] = {
        "ntdll.dll",
        "kernel32.dll",
        "user32.dll",
        "gdi32.dll",
        "msvcrt.dll",
        "advapi32.dll",
        "ws2_32.dll",
        "shell32.dll"
    };

    int moduleCount = sizeof(commonModules) / sizeof(commonModules[0]);

    for (int i = 0; i < moduleCount; i++)
    {
        // 尝试获取模块句柄，如果没有加载则强制加载
        HMODULE hMod = GetModuleHandleA(commonModules[i]);
        if (!hMod)
        {
            hMod = LoadLibraryA(commonModules[i]);
        }

        if (hMod)
        {
            // 尝试查找函数名
            FARPROC proc = GetProcAddress(hMod, apiName);
            if (proc)
            {
                return (DWORD)proc;
            }

            // 很多系统函数分 ANSI 和 Unicode 版本 (如 MessageBoxA / MessageBoxW)
            // 如果用户只输入了 MessageBox，我们自动帮他尝试加 A 和 W 后缀
            char apiNameA[128] = { 0 };
            sprintf_s(apiNameA, sizeof(apiNameA), "%sA", apiName);
            proc = GetProcAddress(hMod, apiNameA);
            if (proc)
            {
                return (DWORD)proc;
            }

            char apiNameW[128] = { 0 };
            sprintf_s(apiNameW, sizeof(apiNameW), "%sW", apiName);
            proc = GetProcAddress(hMod, apiNameW);
            if (proc)
            {
                return (DWORD)proc;
            }
        }
    }

    // 如果所有的常用模块里都找不到，返回 0
    return 0;
}