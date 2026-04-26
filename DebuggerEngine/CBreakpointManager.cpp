#include "CBreakpointManager.h"
#include <stdio.h>
#include <iterator> 

CBreakpointManager::CBreakpointManager() : m_hProcess(NULL), m_pThreadMgr(NULL) {
    ZeroMemory(m_HWBP, sizeof(m_HWBP));
}
CBreakpointManager::~CBreakpointManager() {}

void CBreakpointManager::Init(HANDLE hProcess, CThreadManager* pThreadMgr) {
    m_hProcess = hProcess;
    m_pThreadMgr = pThreadMgr;
    m_BPMap.clear();
    ZeroMemory(m_HWBP, sizeof(m_HWBP));
}

void CBreakpointManager::SetBP(DWORD dwAddr) {
    if (!m_hProcess) return;
    BYTE originalByte;
    if (!ReadProcessMemory(m_hProcess, (LPCVOID)dwAddr, &originalByte, 1, NULL)) {
        printf("SetBP: Read memory failed at 0x%08X\n", dwAddr);
        return;
    }

    BP_INFO bp = { dwAddr, originalByte, TRUE };
    m_BPMap[dwAddr] = bp;

    BYTE cc = 0xCC;
    DWORD oldProtect;
    if (VirtualProtectEx(m_hProcess, (LPVOID)dwAddr, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        WriteProcessMemory(m_hProcess, (LPVOID)dwAddr, &cc, 1, NULL);
        VirtualProtectEx(m_hProcess, (LPVOID)dwAddr, 1, oldProtect, &oldProtect);
        FlushInstructionCache(m_hProcess, (LPCVOID)dwAddr, 1);
        printf("Software Breakpoint set at 0x%08X\n", dwAddr);
    }
    else {
        printf("VirtualProtectEx failed! Error: %d\n", GetLastError());
    }
}

void CBreakpointManager::RemoveBP(DWORD dwAddr) {
    auto it = m_BPMap.find(dwAddr);
    if (it == m_BPMap.end()) {
        printf("Error: No breakpoint found at 0x%08X\n", dwAddr);
        return;
    }
    if (WriteProcessMemory(m_hProcess, (LPVOID)dwAddr, &it->second.originalByte, 1, NULL)) {
        FlushInstructionCache(m_hProcess, (LPCVOID)dwAddr, 1);
        m_BPMap.erase(it);
        printf("Breakpoint removed from 0x%08X\n", dwAddr);
    }
    else {
        printf("Error: Failed to restore memory at 0x%08X\n", dwAddr);
    }
}

void CBreakpointManager::ListBP() {
    if (m_BPMap.empty()) {
        printf("No software breakpoints set.\n");
        return;
    }
    printf("\n--- Software Breakpoints ---\n");
    int index = 0;
    for (auto it = m_BPMap.begin(); it != m_BPMap.end(); ++it) {
        printf("[%d] Address: 0x%08X  |  Status: %s  |  OrigByte: 0x%02X\n",
            index++, it->first, it->second.active ? "Active" : "Disabled", it->second.originalByte);
    }
    printf("----------------------------\n");
}

bool CBreakpointManager::HasBP(DWORD dwAddr) const {
    return m_BPMap.count(dwAddr) > 0;
}

BYTE CBreakpointManager::GetOriginalByte(DWORD dwAddr) {
    if (m_BPMap.count(dwAddr)) return m_BPMap[dwAddr].originalByte;
    return 0;
}

void CBreakpointManager::SetHWBP(DWORD dwAddr, int type, int len) {
    if (!m_pThreadMgr) return;
    int index = -1;
    for (int i = 0; i < 4; i++) {
        if (!m_HWBP[i].active || m_HWBP[i].dwAddr == dwAddr) {
            index = i; break;
        }
    }
    if (index == -1) {
        printf("Error: Hardware breakpoints limit reached (max 4).\n");
        return;
    }

    int len_bit = (len == 1) ? 0 : (len == 2) ? 1 : (len == 4) ? 3 : 0;
    m_HWBP[index] = { dwAddr, type, len, TRUE };

    const auto& threads = m_pThreadMgr->GetThreads();
    for (DWORD tid : threads) {
        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
        if (hThread) {
            CONTEXT ctx = { 0 };
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(hThread, &ctx)) {
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
    printf("Hardware Breakpoint [%d] set at 0x%08X (Type: %d, Len: %d)\n", index, dwAddr, type, len);
}

void CBreakpointManager::RemoveHWBP(DWORD dwAddr) {
    if (!m_pThreadMgr) return;
    int index = -1;
    for (int i = 0; i < 4; i++) {
        if (m_HWBP[i].active && m_HWBP[i].dwAddr == dwAddr) {
            index = i; m_HWBP[i].active = FALSE; m_HWBP[i].dwAddr = 0; break;
        }
    }
    if (index == -1) {
        printf("Error: Hardware breakpoint at 0x%08X not found.\n", dwAddr); return;
    }

    const auto& threads = m_pThreadMgr->GetThreads();
    for (DWORD tid : threads) {
        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
        if (hThread) {
            CONTEXT ctx = { 0 };
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(hThread, &ctx)) {
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
    printf("Hardware Breakpoint removed from 0x%08X\n", dwAddr);
}

void CBreakpointManager::ListHWBP() {
    printf("\n--- Hardware Breakpoints ---\n");
    for (int i = 0; i < 4; i++) {
        if (m_HWBP[i].active) {
            const char* sType = (m_HWBP[i].type == 0) ? "Execute" : (m_HWBP[i].type == 1) ? "Write" : "Read/Write";
            printf("DR%d: 0x%08X | Type: %s | Len: %d\n", i, m_HWBP[i].dwAddr, sType, m_HWBP[i].len);
        }
    }
    printf("----------------------------\n");
}



size_t CBreakpointManager::GetBPCount() const {
    return m_BPMap.size();
}

DWORD CBreakpointManager::GetBPAddr(size_t index) const {
    auto it = m_BPMap.begin();
    std::advance(it, index);
    if (it != m_BPMap.end()) return it->first;
    return 0;
}