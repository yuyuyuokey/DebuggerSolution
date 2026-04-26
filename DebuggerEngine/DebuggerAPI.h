#pragma once
#include <Windows.h>

#ifdef DEBUGGER_ENGINE_EXPORTS
#define DBG_API extern "C" __declspec(dllexport)
#else
#define DBG_API extern "C" __declspec(dllimport)
#endif

#define DBG_EVENT_PAUSED 1  
#define DBG_EVENT_EXITED 2   

typedef void(__stdcall* DEBUG_EVENT_CALLBACK)(int eventType, DWORD dwThreadId);

struct RegInfo
{
    DWORD eax, ebx, ecx, edx;
    DWORD esi, edi, ebp, esp;
    DWORD eip, eflags;
};

struct InstrInfo
{
    DWORD address;
    char hexCode[64];
    char assembly[256];
    char comment[128];
};

struct MemMapItem
{
    DWORD address;
    DWORD size;
    char info[256];
    char protection[16];
    char initProtect[16];
};

struct CallStackItem
{
    DWORD ebp;
    DWORD retTo;
    char moduleName[256];
};

#define BP_TYPE_SOFTWARE 0
#define BP_TYPE_HW_EXECUTE 1
#define BP_TYPE_HW_WRITE 2
#define BP_TYPE_HW_ACCESS 3

struct BPDisplayInfo
{
    DWORD address;
    int type;
    int length;
    bool active;
};

DBG_API bool dbg_Start(const wchar_t* targetPath, DEBUG_EVENT_CALLBACK cb);
DBG_API bool dbg_Attach(DWORD targetPID, DEBUG_EVENT_CALLBACK cb);

DBG_API void dbg_Go();
DBG_API void dbg_StepInto();
DBG_API void dbg_StepOver();
DBG_API void dbg_Pause();
DBG_API void dbg_Stop();
DBG_API void dbg_Restart();
DBG_API void dbg_RunToCursor(DWORD addr);
DBG_API void dbg_RunToReturn();
DBG_API void dbg_RunToUserCode();

DBG_API bool dbg_GetRegs(DWORD dwThreadId, RegInfo* outRegInfo);
DBG_API bool dbg_SetRegister(DWORD dwThreadId, const char* regName, DWORD value);
DBG_API bool dbg_ReadMemory(DWORD address, void* buffer, SIZE_T size);
DBG_API void dbg_EnsureDisasm(DWORD addr);

DBG_API int dbg_GetGlobalDisasmCount();
DBG_API bool dbg_GetGlobalDisasmItem(int index, InstrInfo* outInfo);
DBG_API int dbg_FindDisasmIndexByAddr(DWORD addr);

// ==== 软件断点 API ====
DBG_API bool dbg_SetBreakpoint(DWORD address);
DBG_API bool dbg_RemoveBreakpoint(DWORD address);
DBG_API bool dbg_HasBreakpoint(DWORD address);

// ==== 硬件断点 API ====
DBG_API bool dbg_SetHardwareBreakpoint(DWORD address, int type, int len);
DBG_API bool dbg_RemoveHardwareBreakpoint(DWORD address);
DBG_API bool dbg_HasHardwareBreakpoint(DWORD address);

// ==== 统一断点视图 API ====
DBG_API int dbg_GetTotalBPCount();
DBG_API bool dbg_GetBPInfo(int index, BPDisplayInfo* outInfo);

DBG_API void dbg_UpdateMemoryMap();
DBG_API int dbg_GetMemoryMapCount();
DBG_API bool dbg_GetMemoryMapItem(int index, MemMapItem* outItem);

DBG_API void dbg_UpdateCallStack(DWORD threadId);
DBG_API int dbg_GetCallStackCount();
DBG_API bool dbg_GetCallStackItem(int index, CallStackItem* outItem);

DBG_API DWORD dbg_ResolveApiAddress(const char* apiName);