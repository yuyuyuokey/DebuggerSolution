#pragma once
#include <Windows.h>
#include <vector>
#include "DebuggerAPI.h"

class CDisassembler
{
public:
    CDisassembler();
    ~CDisassembler();

    bool Init();

    // ======== 全局反汇编核心引擎 ========
    bool BuildGlobalDisasm(HANDLE hProcess, DWORD imageBase);
    int GetGlobalCount() const;
    bool GetGlobalItem(int index, InstrInfo* outInfo) const;
    int FindIndexByAddress(DWORD addr) const;
    bool EnsureDisasmForAddress(HANDLE hProcess, DWORD addr);

    // ======== 辅助反汇编功能 ========
    int DisAsm(HANDLE hProcess, DWORD dwAddress, int nLine, DWORD dwThreadId);
    bool IsCallInstruction(BYTE* buffer, SIZE_T length, DWORD& outInstrLength);
    int GetDisasmString(HANDLE hProcess, DWORD dwAddress, int nLine, DWORD dwThreadId, char* outBuffer, int bufferSize);
    int GetDisasmList(HANDLE hProcess, DWORD dwAddress, int nLine, DWORD dwThreadId, InstrInfo* outBuffer);

private:
    BOOL m_bZydisReady;
    DWORD m_dwNextDisasmAddr;
    BOOL m_bHasNextDisasmAddr;

    // 缓存整个代码段的所有指令
    std::vector<InstrInfo> m_GlobalInstrs;

    // 隐藏 Zydis 的结构实现细节
    void* m_pDecoder;
    void* m_pFormatter;

    // 主模块基址与状态
    DWORD m_dwMainModuleBase;
    DWORD m_dwTextVA;
    DWORD m_dwTextSize;
    bool  m_bIsShowingMain;
};