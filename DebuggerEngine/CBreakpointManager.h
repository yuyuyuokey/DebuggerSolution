#pragma once
#include <Windows.h>
#include <map>
#include "CThreadManager.h"

struct BP_INFO {
    DWORD addr;
    BYTE  originalByte;
    BOOL  active;
};

struct HWBP_INFO {
    DWORD dwAddr;
    int type;
    int len;
    BOOL active;
};

class CBreakpointManager
{
public:
    CBreakpointManager();
    ~CBreakpointManager();

    void Init(HANDLE hProcess, CThreadManager* pThreadMgr);

    void SetBP(DWORD dwAddr);
    void RemoveBP(DWORD dwAddr);
    void ListBP();
    bool HasBP(DWORD dwAddr) const;
    BYTE GetOriginalByte(DWORD dwAddr);

    // 【新增】：获取断点总数和具体地址，供断点管理器窗口使用！
    size_t GetBPCount() const;
    DWORD GetBPAddr(size_t index) const;

    void SetHWBP(DWORD dwAddr, int type, int len);
    void RemoveHWBP(DWORD dwAddr);
    void ListHWBP();

private:
    HANDLE m_hProcess;
    CThreadManager* m_pThreadMgr;
    std::map<DWORD, BP_INFO> m_BPMap;
    HWBP_INFO m_HWBP[4];
};