#pragma once
#include <Windows.h>

#ifdef DEBUGGER_ENGINE_EXPORTS
#define DBG_API extern "C" __declspec(dllexport)
#else
#define DBG_API extern "C" __declspec(dllimport)
#endif

// 定义事件类型
#define DBG_EVENT_PAUSED 1   // 调试器暂停
#define DBG_EVENT_EXITED 2   // 目标进程退出

// 定义回调函数指针格式
typedef void(__stdcall* DEBUG_EVENT_CALLBACK)(int eventType, DWORD dwThreadId);

// ==========================================
// 数据结构定义
// ==========================================
struct RegInfo {
    DWORD eax, ebx, ecx, edx;
    DWORD esi, edi, ebp, esp;
    DWORD eip, eflags;
};

// 【修复核心】：大幅扩容缓冲区，彻底杜绝 Buffer is too small
struct InstrInfo {
    DWORD address;         // 指令地址
    char hexCode[64];      // 机器码 (最长15字节*3=45字符，64绝对安全)
    char assembly[256];    // 汇编指令 (与Zydis格式化极限长度对齐)
    char comment[128];
};

// ==========================================
// 导出接口
// ==========================================
DBG_API bool dbg_Start(const wchar_t* targetPath, DEBUG_EVENT_CALLBACK cb);
DBG_API void dbg_Go();
DBG_API void dbg_StepInto();
DBG_API void dbg_StepOver();
DBG_API bool dbg_GetRegs(DWORD dwThreadId, RegInfo* outRegInfo);
DBG_API bool dbg_SetBreakpoint(DWORD address);
DBG_API bool dbg_RemoveBreakpoint(DWORD address);
DBG_API void dbg_EnsureDisasm(DWORD addr);

// 全局反汇编缓存访问接口
DBG_API int dbg_GetGlobalDisasmCount();
DBG_API bool dbg_GetGlobalDisasmItem(int index, InstrInfo* outInfo);
DBG_API int dbg_FindDisasmIndexByAddr(DWORD addr);
DBG_API bool dbg_SetRegister(DWORD dwThreadId, const char* regName, DWORD value);

// 读取目标进程的内存
DBG_API bool dbg_ReadMemory(DWORD address, void* buffer, SIZE_T size);

// 【新增】：导出给 MFC 用的断点查询接口
DBG_API bool dbg_HasBreakpoint(DWORD address);
DBG_API int dbg_GetBPCount();
DBG_API DWORD dbg_GetBPAddress(int index);