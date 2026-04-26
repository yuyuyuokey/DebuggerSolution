#pragma once
#include <Windows.h>
#include <map>
#include "CThreadManager.h"

struct BP_INFO
{
    DWORD addr;
    BYTE  originalByte;
    BOOL  active;
};

struct HWBP_INFO
{
    DWORD dwAddr;
    int   type;
    int   len;
    BOOL  active;
};

class CBreakpointManager
{
public:
    CBreakpointManager();
    ~CBreakpointManager();

    void Init(HANDLE hProcess, CThreadManager* pThreadMgr);

    // ==== 软件断点 ====
    void SetBP(DWORD dwAddr);
    void RemoveBP(DWORD dwAddr);
    void ListBP();
    bool HasBP(DWORD dwAddr) const;
    BYTE GetOriginalByte(DWORD dwAddr);

    size_t GetBPCount() const;
    DWORD GetBPAddr(size_t index) const;

    // ==== 硬件断点 ====
    void SetHWBP(DWORD dwAddr, int type, int len);
    void RemoveHWBP(DWORD dwAddr);
    void ListHWBP();
    bool HasHWBP(DWORD dwAddr) const;

    // 获取硬件断点数组，供 UI 读取
    const HWBP_INFO* GetHWBPArray() const;

private:
    HANDLE m_hProcess;
    CThreadManager* m_pThreadMgr;

    std::map<DWORD, BP_INFO> m_BPMap;
    HWBP_INFO m_HWBP[4]; // x86 架构仅支持 4 个硬件断点 (DR0 - DR3)
};