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

    // ======== 新增的全局反汇编核心引擎 ========
    bool BuildGlobalDisasm(HANDLE hProcess, DWORD imageBase);
    int GetGlobalCount() const;
    bool GetGlobalItem(int index, InstrInfo* outInfo) const;
    int FindIndexByAddress(DWORD addr) const;
    bool EnsureDisasmForAddress(HANDLE hProcess, DWORD addr);
    // ==========================================

    // 执行反汇编并打印，返回打印的行数
    int DisAsm(HANDLE hProcess, DWORD dwAddress, int nLine, DWORD dwThreadId);

    // 用于辅助判断是否是 CALL 指令（为了实现 Step Over）
    bool IsCallInstruction(BYTE* buffer, SIZE_T length, DWORD& outInstrLength);

    // 在 public: 区域增加这个函数
    int GetDisasmString(HANDLE hProcess, DWORD dwAddress, int nLine, DWORD dwThreadId, char* outBuffer, int bufferSize);

    int GetDisasmList(HANDLE hProcess, DWORD dwAddress, int nLine, DWORD dwThreadId, InstrInfo* outBuffer);

private:
    BOOL m_bZydisReady;
    DWORD m_dwNextDisasmAddr;
    BOOL m_bHasNextDisasmAddr;

    // 缓存整个代码段的所有指令
    std::vector<InstrInfo> m_GlobalInstrs;

    // 为了不污染外部头文件，我们将Zydis的结构隐藏为void*，或者直接在CPP实现
    void* m_pDecoder;
    void* m_pFormatter;

    // 【新增】：用来记录主模块的基址和状态
    DWORD m_dwMainModuleBase = 0;
    DWORD m_dwTextVA = 0;
    DWORD m_dwTextSize = 0;
    bool  m_bIsShowingMain = false;
};