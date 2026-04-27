#include "CBreakpointManager.h"
#include <stdio.h>
#include <iterator>

CBreakpointManager::CBreakpointManager() : m_hProcess(NULL), m_pThreadMgr(NULL)
{
    ZeroMemory(m_HWBP, sizeof(m_HWBP));
}

CBreakpointManager::~CBreakpointManager()
{
}

void CBreakpointManager::Init(HANDLE hProcess, CThreadManager* pThreadMgr)
{
    m_hProcess = hProcess;
    m_pThreadMgr = pThreadMgr;

    // 重新应用所有【软件断点】 (把 0xCC 重新写入新进程的内存)
    for (auto& kv : m_BPMap)
    {
        DWORD dwAddr = kv.first;
        BYTE originalByte;

        // 重新读出新进程的原始字节（防止因 ASLR 等机制导致变化）
        if (ReadProcessMemory(m_hProcess, (LPCVOID)dwAddr, &originalByte, 1, NULL))
        {
            kv.second.originalByte = originalByte; // 更新原始字节

            // 重新写入 INT 3 (0xCC) 触发断点
            BYTE cc = 0xCC;
            DWORD oldProtect;
            if (VirtualProtectEx(m_hProcess, (LPVOID)dwAddr, 1, PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                WriteProcessMemory(m_hProcess, (LPVOID)dwAddr, &cc, 1, NULL);
                VirtualProtectEx(m_hProcess, (LPVOID)dwAddr, 1, oldProtect, &oldProtect);
                FlushInstructionCache(m_hProcess, (LPCVOID)dwAddr, 1);
            }
        }
    }

    // 重新应用所有【硬件断点】 (写入新线程的调试寄存器 Dr0~Dr3)
    for (int i = 0; i < 4; i++)
    {
        if (m_HWBP[i].active)
        {
            DWORD addr = m_HWBP[i].dwAddr;
            int type = m_HWBP[i].type;
            int len = m_HWBP[i].len;

            // 设为非活跃，再调用 SetHWBP 重新走一遍设置线程上下文的逻辑
            m_HWBP[i].active = FALSE;
            SetHWBP(addr, type, len);
        }
    }
}

void CBreakpointManager::SetBP(DWORD dwAddr)
{
    if (!m_hProcess || dwAddr == 0) return;

    if (HasBP(dwAddr)) return; // 避免重复下断点

    BYTE originalByte;
    if (!ReadProcessMemory(m_hProcess, (LPCVOID)dwAddr, &originalByte, 1, NULL))
    {
        return;
    }

    BP_INFO bp = { dwAddr, originalByte, TRUE };
    m_BPMap[dwAddr] = bp;

    BYTE cc = 0xCC;
    DWORD oldProtect;

    if (VirtualProtectEx(m_hProcess, (LPVOID)dwAddr, 1, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        WriteProcessMemory(m_hProcess, (LPVOID)dwAddr, &cc, 1, NULL);
        VirtualProtectEx(m_hProcess, (LPVOID)dwAddr, 1, oldProtect, &oldProtect);
        FlushInstructionCache(m_hProcess, (LPCVOID)dwAddr, 1);
    }
}

void CBreakpointManager::RemoveBP(DWORD dwAddr)
{
    if (!m_hProcess || dwAddr == 0) return;

    auto it = m_BPMap.find(dwAddr);
    if (it == m_BPMap.end())
    {
        return;
    }

    DWORD oldProtect;
    // 逻辑修复：移除断点恢复字节时，也需要修改内存页属性，防止因没有写权限导致移除失败
    if (VirtualProtectEx(m_hProcess, (LPVOID)dwAddr, 1, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        WriteProcessMemory(m_hProcess, (LPVOID)dwAddr, &it->second.originalByte, 1, NULL);
        VirtualProtectEx(m_hProcess, (LPVOID)dwAddr, 1, oldProtect, &oldProtect);
        FlushInstructionCache(m_hProcess, (LPCVOID)dwAddr, 1);
    }

    m_BPMap.erase(it);
}

void CBreakpointManager::ListBP()
{
    // 保留给命令行输出使用的接口
}

bool CBreakpointManager::HasBP(DWORD dwAddr) const
{
    return m_BPMap.count(dwAddr) > 0;
}

BYTE CBreakpointManager::GetOriginalByte(DWORD dwAddr)
{
    auto it = m_BPMap.find(dwAddr);
    if (it != m_BPMap.end())
    {
        return it->second.originalByte;
    }
    return 0;
}

size_t CBreakpointManager::GetBPCount() const
{
    return m_BPMap.size();
}

DWORD CBreakpointManager::GetBPAddr(size_t index) const
{
    if (index >= m_BPMap.size()) return 0;

    auto it = m_BPMap.begin();
    std::advance(it, index);
    return it->first;
}

void CBreakpointManager::SetHWBP(DWORD dwAddr, int type, int len)
{
    if (!m_pThreadMgr) return;

    int index = -1;
    for (int i = 0; i < 4; i++)
    {
        if (!m_HWBP[i].active || m_HWBP[i].dwAddr == dwAddr)
        {
            index = i;
            break;
        }
    }

    if (index == -1) return;

    int len_bit = 0;
    if (len == 1) len_bit = 0;
    else if (len == 2) len_bit = 1;
    else if (len == 4) len_bit = 3;

    m_HWBP[index].dwAddr = dwAddr;
    m_HWBP[index].type = type;
    m_HWBP[index].len = len;
    m_HWBP[index].active = TRUE;

    const auto& threads = m_pThreadMgr->GetThreads();
    for (DWORD tid : threads)
    {
        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
        if (hThread)
        {
            CONTEXT ctx = { 0 };
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

            if (GetThreadContext(hThread, &ctx))
            {
                if (index == 0) ctx.Dr0 = dwAddr;
                else if (index == 1) ctx.Dr1 = dwAddr;
                else if (index == 2) ctx.Dr2 = dwAddr;
                else if (index == 3) ctx.Dr3 = dwAddr;

                ctx.Dr7 |= (1 << (index * 2));
                ctx.Dr7 &= ~(0xF << (16 + index * 4));
                ctx.Dr7 |= (type << (16 + index * 4));
                ctx.Dr7 |= (len_bit << (18 + index * 4));

                SetThreadContext(hThread, &ctx);
            }
            CloseHandle(hThread);
        }
    }
}

void CBreakpointManager::RemoveHWBP(DWORD dwAddr)
{
    if (!m_pThreadMgr) return;

    int index = -1;
    for (int i = 0; i < 4; i++)
    {
        if (m_HWBP[i].active && m_HWBP[i].dwAddr == dwAddr)
        {
            index = i;
            m_HWBP[i].active = FALSE;
            m_HWBP[i].dwAddr = 0;
            break;
        }
    }

    if (index == -1) return;

    const auto& threads = m_pThreadMgr->GetThreads();
    for (DWORD tid : threads)
    {
        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
        if (hThread)
        {
            CONTEXT ctx = { 0 };
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

            if (GetThreadContext(hThread, &ctx))
            {
                ctx.Dr7 &= ~(1 << (index * 2));

                if (index == 0) ctx.Dr0 = 0;
                else if (index == 1) ctx.Dr1 = 0;
                else if (index == 2) ctx.Dr2 = 0;
                else if (index == 3) ctx.Dr3 = 0;

                SetThreadContext(hThread, &ctx);
            }
            CloseHandle(hThread);
        }
    }
}

void CBreakpointManager::ListHWBP()
{
    // 保留给命令行输出使用的接口
}

bool CBreakpointManager::HasHWBP(DWORD dwAddr) const
{
    for (int i = 0; i < 4; i++)
    {
        if (m_HWBP[i].active && m_HWBP[i].dwAddr == dwAddr)
        {
            return true;
        }
    }
    return false;
}

const HWBP_INFO* CBreakpointManager::GetHWBPArray() const
{
    return m_HWBP;
}